//! The interface a future ROS graph view would consume. There is no view
//! yet; this fixes the shape of the data so one can be added without
//! changing how graphs are gathered.
//!
//! A [`GraphSnapshot`] is one device's read-only view of its ROS graph,
//! labeled with the device it came from and the domain and RMW the query
//! used. Snapshots of several devices are kept apart rather than merged:
//! two devices that do not discover each other have two different graphs,
//! and that difference is the diagnosis.

use crate::inspect::{Inspection, TopicQos};
use crate::RemoteError;
use serde::Serialize;

/// One endpoint of a topic. Present only for topics whose QoS was queried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GraphEndpoint {
    pub node: String,
    pub publisher: bool,
    pub reliability: String,
    pub durability: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GraphTopic {
    pub name: String,
    pub type_name: String,
    pub endpoints: Vec<GraphEndpoint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GraphSnapshot {
    /// The registered device whose nodes saw this graph.
    pub device: String,
    pub domain: u32,
    pub rmw: String,
    /// Node names (LabLink's own and other `ros2` command-line nodes
    /// excluded).
    pub nodes: Vec<String>,
    pub topics: Vec<GraphTopic>,
}

/// Where a graph view gets its snapshots. Implementations must stay
/// read-only: they may join a domain to listen, never publish.
pub trait GraphSource {
    fn snapshot(&self, device: &str) -> Result<GraphSnapshot, RemoteError>;
}

impl GraphSnapshot {
    /// The snapshot inside an inspection, when its graph query succeeded.
    pub fn from_inspection(i: &Inspection) -> Option<GraphSnapshot> {
        let g = i.graph.as_ref().filter(|g| g.error.is_none())?;
        Some(GraphSnapshot {
            device: i.device.clone(),
            domain: g.domain,
            rmw: g.rmw.clone(),
            nodes: g.nodes.clone(),
            topics: g
                .topics
                .iter()
                .map(|(name, type_name)| GraphTopic {
                    name: name.clone(),
                    type_name: type_name.clone(),
                    endpoints: endpoints(&i.qos, name),
                })
                .collect(),
        })
    }
}

fn endpoints(qos: &[TopicQos], topic: &str) -> Vec<GraphEndpoint> {
    qos.iter()
        .filter(|q| q.topic == topic && q.error.is_none())
        .flat_map(|q| &q.endpoints)
        .map(|e| GraphEndpoint {
            node: e.node.clone(),
            publisher: e.kind == "PUBLISHER",
            reliability: e.reliability.clone(),
            durability: e.durability.clone(),
        })
        .collect()
}
