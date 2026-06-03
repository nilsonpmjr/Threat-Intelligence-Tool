/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { getExtensionStatus, type ExtensionManifest } from "./api";

const POLLING_INTERVAL_MS = 2000;
const MAX_TICKS = 60; // 2 minutes timeout

export async function pollExtensionStatus(
  id: string,
  onUpdate: (manifest: ExtensionManifest) => void,
  onComplete: () => void,
  onError: (error: Error) => void
) {
  let ticks = 0;

  const tick = async () => {
    try {
      const manifest = await getExtensionStatus(id);
      onUpdate(manifest);

      if (manifest.status !== "installing" && manifest.status !== "uninstalling") {
        onComplete();
        return;
      }

      ticks++;
      if (ticks >= MAX_TICKS) {
        onError(new Error("Polling timeout: Extension stuck in transition state for too long."));
        return;
      }

      setTimeout(tick, POLLING_INTERVAL_MS);
    } catch (error) {
      onError(error as Error);
    }
  };

  setTimeout(tick, POLLING_INTERVAL_MS);
}
