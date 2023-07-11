// Layer 1: Udp -> Broadcast encrypted raw packet
// Layer 2; Encripted Tunnel -> Broadcast decrtyped packet
// Layer 3: Routing mechanism -> Compose/Decompose messages
// Layer 4: Resource management
// Layer 5: Network Resources Frontend

// Ingress?
// Egress?

pub mod udp;
pub mod tunnnel;
pub mod routing;



