import bodyParser from "body-parser";
import express, { Request, Response } from "express";
import { REGISTRY_PORT } from "../config";

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



  const server = _registry.listen(REGISTRY_PORT, () => {
    console.log(`Registry is listening on port ${REGISTRY_PORT}`);
  });

  return server;
}