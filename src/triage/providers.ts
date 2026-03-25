import Anthropic from "@anthropic-ai/sdk";
import OpenAI from "openai";
import type { AIProviderConfig } from "../types/index.js";

export interface TriageProvider {
  summarize(prompt: string): Promise<string>;
}

export function createTriageProvider(config?: AIProviderConfig): TriageProvider | null {
  if (!config?.provider) {
    return null;
  }

  switch (config.provider) {
    case "anthropic":
      if (!config.apiKey && !process.env.ANTHROPIC_API_KEY && !process.env.AWS_BEARER_TOKEN_BEDROCK) {
        return null;
      }
      return createAnthropicProvider(config);
    case "openai":
      if (!config.apiKey && !process.env.OPENAI_API_KEY) {
        return null;
      }
      return createOpenAIProvider(config);
    case "ollama":
      return createOllamaProvider(config);
    default:
      return null;
  }
}

function createAnthropicProvider(config: AIProviderConfig): TriageProvider {
  const bedrockToken = process.env.AWS_BEARER_TOKEN_BEDROCK;
  const isAWSBedrock = !!(config.baseUrl?.includes("bedrock") || bedrockToken);

  if (isAWSBedrock) {
    return createBedrockProvider(config, bedrockToken!);
  }

  const client = new Anthropic({
    apiKey: config.apiKey ?? process.env.ANTHROPIC_API_KEY,
  });
  const model = config.model ?? "claude-3-5-sonnet-latest";

  return {
    async summarize(prompt: string): Promise<string> {
      const response = await client.messages.create({
        model,
        max_tokens: 800,
        system:
          "You are PenClaw, a security triage engine. Return concise JSON-compatible prose focused on exploitability, false-positive risk, proof of concept, and a concrete fix.",
        messages: [{ role: "user", content: prompt }],
      });

      return response.content
        .filter((block) => block.type === "text")
        .map((block) => block.text)
        .join("\n")
        .trim();
    },
  };
}

function createOpenAIProvider(config: AIProviderConfig): TriageProvider {
  const client = new OpenAI({
    apiKey: config.apiKey ?? process.env.OPENAI_API_KEY,
    baseURL: config.baseUrl,
  });
  const model = config.model ?? "gpt-4.1-mini";

  return {
    async summarize(prompt: string): Promise<string> {
      const response = await client.responses.create({
        model,
        input: [
          {
            role: "system",
            content:
              "You are PenClaw, a security triage engine. Return concise JSON-compatible prose focused on exploitability, false-positive risk, proof of concept, and a concrete fix.",
          },
          {
            role: "user",
            content: prompt,
          },
        ],
      });

      return response.output_text.trim();
    },
  };
}

function createOllamaProvider(config: AIProviderConfig): TriageProvider {
  const baseUrl = config.baseUrl ?? "http://127.0.0.1:11434";
  const model = config.model ?? "llama3.1";

  return {
    async summarize(prompt: string): Promise<string> {
      const response = await fetch(`${baseUrl}/api/generate`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          model,
          prompt:
            "You are PenClaw, a security triage engine. Return concise JSON-compatible prose focused on exploitability, false-positive risk, proof of concept, and a concrete fix.\n\n" +
            prompt,
          stream: false,
        }),
      });

      if (!response.ok) {
        throw new Error(`Ollama request failed with ${response.status}`);
      }

      const data = (await response.json()) as { response?: string };
      return data.response?.trim() ?? "";
    },
  };
}

function createBedrockProvider(config: AIProviderConfig, token: string): TriageProvider {
  const baseUrl = config.baseUrl ?? "https://bedrock-runtime.us-east-1.amazonaws.com";
  const model = config.model ?? "us.anthropic.claude-sonnet-4-20250514-v1:0";

  return {
    async summarize(prompt: string): Promise<string> {
      const response = await fetch(`${baseUrl}/model/${model}/invoke`, {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          anthropic_version: "bedrock-2023-05-31",
          system:
            "You are PenClaw, a security triage engine. Return concise JSON-compatible prose focused on exploitability, false-positive risk, proof of concept, and a concrete fix.",
          messages: [{ role: "user", content: prompt }],
          max_tokens: 800,
        }),
      });

      if (!response.ok) {
        const errorBody = await response.text().catch(() => "");
        throw new Error(`Bedrock request failed with ${response.status}: ${errorBody.slice(0, 200)}`);
      }

      const data = (await response.json()) as {
        content?: Array<{ type: string; text?: string }>;
      };

      return (data.content ?? [])
        .filter((block) => block.type === "text")
        .map((block) => block.text ?? "")
        .join("\n")
        .trim();
    },
  };
}
