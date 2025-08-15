package utils

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cassette/sdk/config"
	"golang.org/x/exp/maps"
)

type Network string

const MainNet Network = "mainnet"
const TestNet Network = "testnet"

// the status.neofs data structure

type JSONData struct {
	Status            map[string]string      `json:"status"`
	StatusMsgs        map[string][]string    `json:"statusmsgs"`
	NetworkEpoch      map[string]float64     `json:"network_epoch"`
	Containers        map[string]float64     `json:"containers"`
	Time              float64                `json:"time"`
	NodeMap           []NodeMap              `json:"node_map"`
	Contract          map[string]Contract    `json:"contract"`
	Gateways          map[string][][]string  `json:"gateways"`
	SideChainRPCNodes map[string][][]string  `json:"side_chain_rpc_nodes"`
	StorageNodes      map[string][][]string  `json:"storage_nodes"`
	NeoGoRPCNodes     map[string][][]RPCNode `json:"neo_go_rpc_nodes"`
}

type NodeMap struct {
	Latitude  string `json:"latitude"`
	Location  string `json:"location"`
	Longitude string `json:"longitude"`
	Nodes     []Node `json:"nodes"`
}

type Node struct {
	Net   string  `json:"net"`
	Value float64 `json:"value"`
}

type Contract struct {
	Address    string `json:"address"`
	ScriptHash string `json:"script_hash"`
}

// currently out network data structure
type NetworkData struct {
	Name         string
	ID           string
	Address      string
	SidechainRPC []string
	StorageNodes map[string]config.Peer
	RpcNodes     []RPCNode
}
type NodeSelection struct {
	Nodes   []config.Peer
	current int
}

var networks = map[Network]NetworkData{}

//fixme - this should not be how we do this it should be loaded dynamically

func init() {
	networks = defaultNetworkData
}

func (s *NodeSelection) getNext() (config.Peer, error) {
	if s.current == len(s.Nodes)-1 {
		return config.Peer{}, errors.New("Could not connect to any nodes, please try later")
	}
	node := s.Nodes[s.current]
	s.current = s.current + 1 // % len(s.Nodes) unless we want truly round robin connections...
	return node, nil
}

func NewNetworkSelector(nodes []config.Peer) NodeSelection {
	nodeSelection := NodeSelection{
		Nodes:   nodes,
		current: 0,
	}
	return nodeSelection
}
func RetrieveStoragePeers(n Network) []config.Peer {
	return maps.Values(networks[n].StorageNodes)
}
func RetrieveRPCNodes(n Network) []RPCNode {
	return networks[n].RpcNodes
}
func RetrieveNetworkFileSystemAddress(n Network) NetworkData {
	return networks[n]
}

func LoadNetworkData(jsonBytes []byte) (map[Network]NetworkData, error) {
	var jsonData JSONData
	if err := json.Unmarshal(jsonBytes, &jsonData); err != nil {
		return nil, err
	}

	networks := make(map[Network]NetworkData)

	// Transform JSONData into map[Network]NetworkData
	for networkType, contract := range jsonData.Contract {
		var sidechainRPC []string
		for _, rpc := range jsonData.SideChainRPCNodes[networkType] {
			sidechainRPC = append(sidechainRPC, rpc[0]) // Assuming you want the first URL
		}

		storageNodes := make(map[string]config.Peer)
		for i, node := range jsonData.StorageNodes[networkType] {
			storageNodes[fmt.Sprintf("%d", i)] = config.Peer{
				Address:  node[0], // Assuming you want the first URL
				Priority: i + 1,
				Weight:   1,
			}
		}

		var rpcNodes []RPCNode
		for _, rpc := range jsonData.NeoGoRPCNodes[networkType] {
			rpcNodes = append(rpcNodes, rpc[0]) // Assuming you want the first URL
		}

		networks[Network(networkType)] = NetworkData{
			Name:         networkType,
			ID:           networkType,
			Address:      contract.Address,
			SidechainRPC: sidechainRPC,
			StorageNodes: storageNodes,
			RpcNodes:     rpcNodes,
		}
	}

	return networks, nil
}

var defaultNetworkData = map[Network]NetworkData{
	"mainnet": {
		Name:    "mainnet",
		ID:      "mainnet",
		Address: "NNxVrKjLsRkWsmGgmuNXLcMswtxTGaNQLk",
		SidechainRPC: []string{
			"https://rpc1.morph.fs.neo.org:40341",
			"https://rpc2.morph.fs.neo.org:40341",
			"https://rpc3.morph.fs.neo.org:40341",
			"https://rpc4.morph.fs.neo.org:40341",
			"https://rpc5.morph.fs.neo.org:40341",
			"https://rpc6.morph.fs.neo.org:40341",
			"https://rpc7.morph.fs.neo.org:40341",
		},
		StorageNodes: map[string]config.Peer{
			"0": {
				Address:  "grpcs://st1.storage.fs.neo.org:8082",
				Priority: 1,
				Weight:   1,
			},
			"1": {
				Address:  "grpcs://st2.storage.fs.neo.org:8082",
				Priority: 2,
				Weight:   1,
			},
			"2": {
				Address:  "grpcs://st3.storage.fs.neo.org:8082",
				Priority: 3,
				Weight:   1,
			},
			"3": {
				Address:  "grpcs://st4.storage.fs.neo.org:8082",
				Priority: 4,
				Weight:   1,
			},
		},
		RpcNodes: []RPCNode{{
			HTTP: "https://rpc10.n3.nspcc.ru:10331",
			WS:   "wss://rpc10.n3.nspcc.ru:10331/ws",
		},
		},
	},
	"testnet": {
		Name:    "testnet",
		ID:      "testnet",
		Address: "NZAUkYbJ1Cb2HrNmwZ1pg9xYHBhm2FgtKV",
		SidechainRPC: []string{
			"https://rpc1.morph.t5.fs.neo.org:51331",
			"https://rpc2.morph.t5.fs.neo.org:51331",
			"https://rpc3.morph.t5.fs.neo.org:51331",
			"https://rpc4.morph.t5.fs.neo.org:51331",
			"https://rpc5.morph.t5.fs.neo.org:51331",
			"https://rpc6.morph.t5.fs.neo.org:51331",
			"https://rpc7.morph.t5.fs.neo.org:51331",
		},
		StorageNodes: map[string]config.Peer{
			"0": {
				Address:  "grpcs://st1.t5.fs.neo.org:8082",
				Priority: 1,
				Weight:   1,
			},
			"1": {
				Address:  "grpcs://st2.t5.fs.neo.org:8082",
				Priority: 2,
				Weight:   1,
			},
			"2": {
				Address:  "grpcs://st3.t5.fs.neo.org:8082",
				Priority: 3,
				Weight:   1,
			},
			"3": {
				Address:  "grpcs://st4.t5.fs.neo.org:8082",
				Priority: 4,
				Weight:   1,
			},
		},
		RpcNodes: []RPCNode{{
			HTTP: "https://rpc.t5.n3.nspcc.ru:20331",
			WS:   "wss://rpc.t5.n3.nspcc.ru:20331/ws",
		},
		},
	},
}

type RPCNode struct {
	HTTP string
	WS   string
}
