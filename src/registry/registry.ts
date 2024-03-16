import bodyParser from "body-parser";
import express, { Request, Response } from "express";
import { REGISTRY_PORT } from "../config";
import { generateRsaKeyPair, exportPrvKey } from "../crypto";

export type Node = { nodeId: number; pubKey: string };

export type RegisterNodeBody = {
  nodeId: number;
  pubKey: string;
};

export type GetNodeRegistryBody = {
  nodes: Node[];
};

const nodeRegistry: Node[] = [];

export async function launchRegistry() {
  const _registry = express();
  _registry.use(express.json());
  _registry.use(bodyParser.json());

  _registry.get("/status", (req, res) => {
    res.send("live");
  });

  _registry.get("/getNodeRegistry", (req, res) => {
    const responseBody: GetNodeRegistryBody = { nodes: nodeRegistry };
    res.json(responseBody);
  });

  _registry.post("/registerNode", (req: Request<{}, {}, RegisterNodeBody>, res: Response) => {
    const { nodeId, pubKey } = req.body;

    if (!nodeId || !pubKey) {
      return res.status(400).json({ error: "Node ID and public key are required for registration" });
    }

    const newNode: Node = { nodeId, pubKey };
    nodeRegistry.push(newNode);

    return res.status(201).json({ message: "Node registered successfully" });
  });
  interface PrivateKeyRegistry {
    [nodeId: string]: string;
  }

// In-memory registry to store nodes' private keys
  const privateKeys: PrivateKeyRegistry = {};


  _registry.get("/getPrivateKey/:nodeId", async (req: Request, res: Response) => {
    const nodeId = req.params.nodeId;

    // Check if private key for the node already exists
    if (privateKeys[nodeId]) {
      return res.json({ result: privateKeys[nodeId] });
    }

    try {
      // Generate RSA key pair
      const { privateKey } = await generateRsaKeyPair();

      // Convert private key to string
      const privateKeyString = await exportPrvKey(privateKey);

      // Check if privateKeyString is not null
      if (privateKeyString !== null) {
        // Store private key in the registry
        privateKeys[nodeId] = privateKeyString;

        return res.json({ result: privateKeyString });
      } else {
        // Handle the case where privateKeyString is null
        return res.status(500).json({ error: "Internal Server Error" });
      }
    } catch (error) {
      console.error("Error generating private key:", error);
      return res.status(500).json({ error: "Internal Server Error" });
    }
  });


  const server = _registry.listen(REGISTRY_PORT, () => {
    console.log(`Registry is listening on port ${REGISTRY_PORT}`);
  });

  return server;
}