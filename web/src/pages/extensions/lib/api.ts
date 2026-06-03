/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import API_URL from "../../../config";

export type ExtensionStatus = 
  | "not_installed" 
  | "installing" 
  | "installed_healthy" 
  | "installed_unhealthy" 
  | "stopped" 
  | "installing_failed" 
  | "uninstalling";

export interface ExtensionManifest {
  id: string;
  name: string;
  description: string;
  version: string;
  status: ExtensionStatus;
  installed_at: string | null;
  last_health_ts: string | null;
  last_error: string | null;
  settings: Record<string, any>;
  operations: string[];
  requires: {
    docker_socket_proxy: boolean;
    disk_space_mb: number;
    ports: number[];
  };
  settings_schema: Array<{
    key: string;
    type: "boolean" | "string" | "integer";
    default: any;
    label: string;
  }>;
  uninstall: {
    destroy_volumes_by_default: boolean;
    confirm_phrase: string;
  };
  locked_by: null | {
    action: string;
    user: string;
    started_at: string;
  };
  secrets_present?: Record<string, string>; // name -> timestamp
  secrets?: Array<{ name: string }>; // For rendering the list
}

export async function listExtensions(): Promise<ExtensionManifest[]> {
  const response = await fetch(`${API_URL}/api/extensions`, {
    credentials: "include",
  });
  if (!response.ok) throw new Error("Failed to list extensions");
  const data = await response.json();
  return data.extensions;
}

export async function getExtension(id: string): Promise<ExtensionManifest> {
  const response = await fetch(`${API_URL}/api/extensions/${id}`, {
    credentials: "include",
  });
  if (!response.ok) throw new Error(`Failed to get extension ${id}`);
  return await response.json();
}

export async function getExtensionStatus(id: string): Promise<ExtensionManifest> {
  const response = await fetch(`${API_URL}/api/extensions/${id}/status`, {
    credentials: "include",
  });
  if (!response.ok) throw new Error(`Failed to get status for ${id}`);
  return await response.json();
}

export async function installExtension(id: string): Promise<{ task_id: string; status: string }> {
  const response = await fetch(`${API_URL}/api/extensions/${id}/install`, {
    method: "POST",
    credentials: "include",
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.message || "Failed to install extension");
  }
  return await response.json();
}

export async function uninstallExtension(
  id: string, 
  confirmPhrase: string, 
  destroyVolumes?: boolean
): Promise<{ task_id: string; status: string }> {
  const response = await fetch(`${API_URL}/api/extensions/${id}/uninstall`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ confirm_phrase: confirmPhrase, destroy_volumes: destroyVolumes }),
    credentials: "include",
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.message || "Failed to uninstall extension");
  }
  return await response.json();
}

export async function startExtension(id: string): Promise<ExtensionManifest> {
  const response = await fetch(`${API_URL}/api/extensions/${id}/start`, {
    method: "POST",
    credentials: "include",
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.message || "Failed to start extension");
  }
  return await response.json();
}

export async function stopExtension(id: string): Promise<ExtensionManifest> {
  const response = await fetch(`${API_URL}/api/extensions/${id}/stop`, {
    method: "POST",
    credentials: "include",
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.message || "Failed to stop extension");
  }
  return await response.json();
}

export async function restartExtension(id: string): Promise<ExtensionManifest> {
  const response = await fetch(`${API_URL}/api/extensions/${id}/restart`, {
    method: "POST",
    credentials: "include",
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.message || "Failed to restart extension");
  }
  return await response.json();
}

export async function updateExtensionSettings(id: string, settings: Record<string, any>): Promise<{ settings: Record<string, any> }> {
  const response = await fetch(`${API_URL}/api/extensions/${id}/settings`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ settings }),
    credentials: "include",
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.message || "Failed to update settings");
  }
  return await response.json();
}

export async function rotateExtensionSecret(id: string, secretName: string): Promise<{ rotated: string }> {
  const response = await fetch(`${API_URL}/api/extensions/${id}/secrets/${secretName}/rotate`, {
    method: "POST",
    credentials: "include",
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.message || "Failed to rotate secret");
  }
  return await response.json();
}
