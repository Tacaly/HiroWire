use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tera::{Context, Tera};
use wg_config::{Interface, Key, Peer};

// ===============
// CONFIGURATION
// ===============
// !!! IMPORTANT: Fill these in with your OPNsense details !!!
const OPN_API_KEY: &str = "YOUR_OPNSENSE_API_KEY";
const OPN_API_SECRET: &str = "YOUR_OPNSENSE_API_SECRET";
// Example: "https://opnsense.my-domain.com"
const OPN_BASE_URL: &str = "https://your-opnsense-domain.com";
// Example: "https://wg.my-domain.com:51820"
const WG_SERVER_ENDPOINT: &str = "your-wireguard-endpoint.com:51820";
// Find this in the OPNsense UI or via API
const WG_SERVER_PUBLIC_KEY: &str = "YOUR_WG_SERVER_PUBLIC_KEY";
// This is the UUID of the OPNsense WireGuard *server instance*
const OPN_SERVER_UUID: &str = "YOUR_OPNSENSE_SERVER_INSTANCE_UUID";
// This is the UUID of the OPNsense WireGuard *local instance*
// Often, you need to call reconfigure on this. Check OPNsense docs.
const OPN_WG_INSTANCE_UUID: &str = "YOUR_OPNSENSE_WG_LOCAL_INSTANCE_UUID";

// ===============
// WEB FORM STRUCT
// ===============
/// This struct receives the data from the HTML form.
#[derive(Deserialize, Debug)]
pub struct WireGuardRequest {
    client_name: String,
    // We take strings and parse them, providing errors back to the user if they fail.
    client_address_v4: String,
    client_address_v6: String,
    push_to_opnsense: Option<String>, // HTML forms send "on" for checkboxes

    // Fields for "uploading" (pasting) existing keys
    existing_public_key: Option<String>,
    existing_preshared_key: Option<String>,
}

// ===============
// OPNsense API STRUCTS
// ===============
/// This struct matches the JSON payload OPNsense expects to add a new peer.
#[derive(Serialize)]
struct OpnsenseAddPeerPayload<'a> {
    enabled: &'a str,
    name: &'a str,
    pubkey: &'a str,
    allowedips: String, // OPNsense likes comma-separated strings
    psk: &'a str, // Pre-shared key
}

/// A simple struct for deleting a peer
#[derive(Deserialize, Debug)]
pub struct DeletePeerRequest {
    uuid: String,
}

// ===============
// KEY GENERATION
// ===============
/// A simple container for a client's generated keys.
#[derive(Debug, Serialize)]
struct ClientKeys {
    #[serde(skip_serializing)] // Don't send private key to template
    private_key: Key,
    public_key: String,
    preshared_key: String,
}

/// This function generates a new set of WireGuard keys for a client.
fn generate_client_keys() -> ClientKeys {
    let client_private_key = Key::generate();
    let client_public_key = client_private_key.public_key();
    let client_preshared_key = Key::generate(); // Generate PSK

    ClientKeys {
        private_key: client_private_key,
        public_key: client_public_key.to_string(),
        preshared_key: client_preshared_key.to_string(),
    }
}

// ===============
// OPNsense API CLIENT (Re-usable)
// ===============

/// A re-usable client for OPNsense API calls
/// Note: Switched to reqwest::blocking::Client for simplicity in handlers
/// Note: Disabling cert validation is DANGEROUS for production.
/// Use a proper trust chain in a real app.
fn opnsense_api_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true) // Allow self-signed certs
        .build()
        .unwrap()
}

/// Applies the WireGuard configuration on OPNsense
fn apply_opnsense_config() -> Result<String, String> {
    let client = opnsense_api_client();
    let apply_url = format!(
        "{}/api/wireguard/service/reconfigure/{}",
        OPN_BASE_URL, OPN_WG_INSTANCE_UUID
    );

    let apply_response = client
        .post(&apply_url)
        .basic_auth(OPN_API_KEY, Some(OPN_API_SECRET))
        .send();

    match apply_response {
        Ok(res) if res.status().is_success() => Ok("Config applied".to_string()),
        Ok(res) => Err(format!(
            "OPNsense APPLY failed: {}",
            res.text().unwrap_or_default()
        )),
        Err(e) => Err(format!("OPNsense APPLY connection error: {}", e)),
    }
}

// ===============
// WEB HANDLERS
// ===============

/// GET / - Renders the main index page (Generate)
#[get("/")]
async fn index(tera: web::Data<Tera>) -> impl Responder {
    let mut context = Context::new();
    context.insert("title", "Generate Peer");
    context.insert("error", "");
    context.insert("client_config", "");
    context.insert("opnsense_status", "");
    context.insert("active_page", "generate"); // For sidebar
    match tera.render("index.html", &context) {
        Ok(rendered) => HttpResponse::Ok().body(rendered),
        Err(e) => {
            eprintln!("Template error: {}", e);
            HttpResponse::InternalServerError().body("Template error")
        }
    }
}

/// GET /peers - Renders the "Manage Peers" page
#[get("/peers")]
async fn peers_page(tera: web::Data<Tera>) -> impl Responder {
    let mut context = Context::new();
    context.insert("title", "Manage Peers");
    context.insert("active_page", "manage"); // For sidebar
    match tera.render("peers.html", &context) {
        Ok(rendered) => HttpResponse::Ok().body(rendered),
        Err(e) => {
            eprintln!("Template error: {}", e);
            HttpResponse::InternalServerError().body("Template error")
        }
    }
}

/// POST / - Handles the form submission
#[post("/")]
async fn generate_config(
    tera: web::Data<Tera>,
    form: web::Form<WireGuardRequest>,
) -> impl Responder {
    let mut context = Context::new();
    context.insert("title", "Generate Peer");
    context.insert("active_page", "generate");
    context.insert("form_data", &form); // Send back form data to re-fill fields

    // --- 1. Validate IPs ---
    let client_ipv4: Ipv4Net = match form.client_address_v4.parse() {
        Ok(ip) => ip,
        Err(_) => {
            context.insert("error", "Invalid IPv4 Address. Must be CIDR (e.g., 10.0.1.5/32)");
            let rendered = tera.render("index.html", &context).unwrap();
            return HttpResponse::BadRequest().body(rendered);
        }
    };
    let client_ipv6: Ipv6Net = match form.client_address_v6.parse() {
        Ok(ip) => ip,
        Err(_) => {
            context.insert("error", "Invalid IPv6 Address. Must be CIDR (e.g., fd10:0:1::5/128)");
            let rendered = tera.render("index.html", &context).unwrap();
            return HttpResponse::BadRequest().body(rendered);
        }
    };

    let mut client_config_string: Option<String> = None;
    let public_key_str: String;
    let psk_str: String;

    // --- 2. Generate Keys OR Use Existing ---
    if let (Some(pubkey), Some(psk)) = (
        form.existing_public_key.as_deref(),
        form.existing_preshared_key.as_deref(),
    ) {
        if !pubkey.trim().is_empty() && !psk.trim().is_empty() {
            // --- Use Existing Key ---
            println!("Using existing key for: {}", form.client_name);
            public_key_str = pubkey.trim().to_string();
            psk_str = psk.trim().to_string();
            client_config_string = None; // Can't generate config without private key
            context.insert("opnsense_status", "Adding existing peer to OPNsense. No config file can be generated.");
        } else {
            // --- Generate New Key ---
            let client_keys = generate_client_keys();
            public_key_str = client_keys.public_key.clone();
            psk_str = client_keys.preshared_key.clone();

            // Pass keys to template for download
            context.insert("client_private_key", &client_keys.private_key.to_string());
            context.insert("client_public_key", &client_keys.public_key);
            context.insert("client_preshared_key", &client_keys.preshared_key);

            let server_public_key: Key = WG_SERVER_PUBLIC_KEY.parse().expect("Invalid server public key");
            let mut server_peers = BTreeMap::new();
            let server_peer = Peer {
                public_key: server_public_key,
                allowed_ips: vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
                endpoint: Some(WG_SERVER_ENDPOINT.parse().expect("Invalid server endpoint")),
                preshared_key: Some(client_keys.preshared_key.parse().unwrap()),
                ..Default::default()
            };
            server_peers.insert(server_public_key, server_peer);
            let client_interface = Interface {
                private_key: client_keys.private_key,
                address: vec![IpNet::V4(client_ipv4), IpNet::V6(client_ipv6)],
                peers: server_peers,
                ..Default::default()
            };
            client_config_string = Some(client_interface.to_string());
        }
    } else {
        // --- Fallback to Generate New Key ---
        let client_keys = generate_client_keys();
        public_key_str = client_keys.public_key.clone();
        psk_str = client_keys.preshared_key.clone();

        // Pass keys to template for download
        context.insert("client_private_key", &client_keys.private_key.to_string());
        context.insert("client_public_key", &client_keys.public_key);
        context.insert("client_preshared_key", &client_keys.preshared_key);

        let server_public_key: Key = WG_SERVER_PUBLIC_KEY.parse().expect("Invalid server public key");
        let mut server_peers = BTreeMap::new();
        let server_peer = Peer {
            public_key: server_public_key,
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
            endpoint: Some(WG_SERVER_ENDPOINT.parse().expect("Invalid server endpoint")),
            preshared_key: Some(client_keys.preshared_key.parse().unwrap()),
            ..Default::default()
        };
        server_peers.insert(server_public_key, server_peer);
        let client_interface = Interface {
            private_key: client_keys.private_key,
            address: vec![IpNet::V4(client_ipv4), IpNet::V6(client_ipv6)],
            peers: server_peers,
            ..Default::default()
};
        client_config_string = Some(client_interface.to_string());
    }

    if let Some(config_str) = &client_config_string {
        context.insert("client_config", config_str);
    }

    // --- 3. Push to OPNsense (if checked) ---
    if form.push_to_opnsense.is_some() {
        println!("Pushing to OPNsense for: {}", form.client_name);

        let allowed_ips = format!("{},{}", client_ipv4, client_ipv6);
        let opnsense_payload = OpnsenseAddPeerPayload {
            enabled: "1",
            name: &form.client_name,
            pubkey: &public_key_str,
            allowedips: allowed_ips,
            psk: &psk_str,
        };

        let client = opnsense_api_client();
        let add_peer_url = format!(
            "{}/api/wireguard/server/addPeer/{}",
            OPN_BASE_URL, OPN_SERVER_UUID
        );

        let add_response = client
            .post(&add_peer_url)
            .basic_auth(OPN_API_KEY, Some(OPN_API_SECRET))
            .json(&opnsense_payload)
            .send();

        match add_response {
            Ok(res) if res.status().is_success() => {
                println!("Successfully added peer. Now applying changes...");
                match apply_opnsense_config() {
                    Ok(_) => context.insert("opnsense_status", "Success! Peer added and applied."),
                    Err(e) => context.insert("opnsse_status", &format!("Peer added, but APPLY FAILED: {}", e)),
                };
            }
            Ok(res) => {
                let error_msg =
                    format!("OPNsense ADD PEER failed: {}", res.text().unwrap_or_default());
                context.insert("opnsense_status", &error_msg);
            }
            Err(e) => {
                let error_msg = format!("OPNsense ADD PEER connection error: {}", e);
                context.insert("opnsense_status", &error_msg);
            }
        }
    }

    // --- 4. Render final page ---
    let rendered = tera.render("index.html", &context).unwrap();
    HttpResponse::Ok().body(rendered)
}

/// GET /api/peers - Returns a list of all peers from OPNsense
#[get("/api/peers")]
async fn get_peers() -> impl Responder {
    let client = opnsense_api_client();
    let search_url = format!(
        "{}/api/wireguard/server/searchPeer/{}",
        OPN_BASE_URL, OPN_SERVER_UUID
    );

    let search_response = client
        .get(&search_url)
        .basic_auth(OPN_API_KEY, Some(OPN_API_SECRET))
        .send();

    match search_response {
        Ok(res) if res.status().is_success() => {
            let body = res.text().unwrap_or_default();
            HttpResponse::Ok()
                .content_type("application/json")
                .body(body)
        }
        Ok(res) => HttpResponse::InternalServerError().body(format!(
            "Failed to fetch peers: {}",
            res.text().unwrap_or_default()
        )),
        Err(e) => HttpResponse::InternalServerError().body(format!("Connection error: {}", e)),
    }
}

/// POST /api/delete_peer - Deletes a peer from OPNsense
#[post("/api/delete_peer")]
async fn delete_peer(req: web::Json<DeletePeerRequest>) -> impl Responder {
    let client = opnsense_api_client();
    let delete_url = format!(
        "{}/api/wireguard/server/delPeer/{}",
        OPN_BASE_URL, req.uuid
    );

    let delete_response = client
        .post(&delete_url)
        .basic_auth(OPN_API_KEY, Some(OPN_API_SECRET))
        .send();

    match delete_response {
        Ok(res) if res.status().is_success() => {
            // After deleting, we must apply the config
            match apply_opnsense_config() {
                Ok(_) => HttpResponse::Ok().json(&serde_json::json!({"status": "deleted"})),
                Err(e) => HttpResponse::InternalServerError().body(e),
            }
        }
        Ok(res) => HttpResponse::InternalServerError().body(format!(
            "Failed to delete peer: {}",
            res.text().unwrap_or_default()
        )),
        Err(e) => HttpResponse::InternalServerError().body(format!("Connection error: {}", e)),
    }
}

// ===============
// MAIN FUNCTION
// ===============
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // IMPORTANT: Bind to 0.0.0.0 to be accessible from inside a Docker container
    let bind_address = "0.0.0.0:8080";
    println!("Starting server at http://{}", bind_address);

    // This is for reqwest, to tell it to use the rustls-native-certs store
    // This helps in finding system certs.
    std::env::set_var("RUSTLS_NATIVE_CERTS", "1");

    HttpServer::new(|| {
        let tera = Tera::new("templates/**/*").expect("Tera template glob failed");

        App::new()
            .app_data(web::Data::new(tera))
            .service(index)
            .service(peers_page) // Add new page
            .service(generate_config)
            // API ENDPOINTS
            .service(get_peers)
            .service(delete_peer)
    })
    .bind(bind_address)?
    .run()
    .await
}