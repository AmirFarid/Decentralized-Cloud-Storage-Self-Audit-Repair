# P2P Network Package

A reusable C package that enables peer-to-peer communication between multiple nodes. The package supports multiple simultaneous TCP connections, uses threads for concurrent messaging, and provides a clean API for integration into larger systems.

## Features

- Act as both server and client
- Support multiple simultaneous TCP connections
- Thread-based concurrent messaging
- Message identification by sender
- Clean and simple API
- Optional logging for debugging
- Easy integration with larger systems (e.g., SGX)

## Building

To build the package and example:

```bash
make
```

To clean build files:

```bash
make clean
```

## Usage Example

The package includes an example that demonstrates two nodes communicating with each other. To run the example:

1. Start the first node:
```bash
./bin/p2p_example node1 8000 0
```

2. Start the second node:
```bash
./bin/p2p_example node2 8001 8000
```

The command line arguments are:
- `node_id`: Unique identifier for the node
- `listen_port`: Port to listen for incoming connections
- `peer_port`: Port of the peer to connect to (0 if no peer)

### Sending Messages

Once the nodes are running, you can send messages using the format:
```
<peer_id> <message>
```

For example:
```
node2 Hello from node1!
```

## API

### Initialization and Cleanup

```c
Node* p2p_node_init(const NodeConfig* config);
void p2p_node_cleanup(Node* node);
```

### Node Control

```c
int p2p_node_start(Node* node);
void p2p_node_stop(Node* node);
```

### Peer Management

```c
int p2p_connect_to_peer(Node* node, const char* ip_address, uint16_t port);
int p2p_disconnect_peer(Node* node, const char* peer_id);
int p2p_get_peer_count(const Node* node);
PeerConnection* p2p_get_peer_info(Node* node, const char* peer_id);
```

### Messaging

```c
int p2p_send_to_peer(Node* node, const char* peer_id, const Message* message);
int p2p_broadcast(Node* node, const Message* message);
```

### Configuration

```c
void p2p_set_logging(Node* node, bool enable);
```

## Message Structure

```c
typedef struct {
    MessageType type;
    char sender_id[MAX_PEER_ID_LENGTH];
    uint32_t data_length;
    uint8_t data[MAX_MESSAGE_SIZE];
} Message;
```

## Integration with SGX

To integrate this package with SGX:

1. Include the header files in your SGX project
2. Compile the source files with your SGX project
3. Use the API within your enclave code
4. Ensure proper memory management within the enclave

## License

This package is released under the MIT License. See the LICENSE file for details. 