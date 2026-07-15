import { world, system } from "@minecraft/server";

// One zap per second per player, so nobody floods the world with lightning.
const COOLDOWN_TICKS = 20;
const MAX_RANGE = 64;

const lastZapTick = new Map();

world.afterEvents.itemUse.subscribe((event) => {
  const player = event.source;
  if (event.itemStack?.typeId !== "demo:zap_wand") return;

  const now = system.currentTick;
  const last = lastZapTick.get(player.id);
  if (last !== undefined && now - last < COOLDOWN_TICKS) return;

  const hit = player.getBlockFromViewDirection({ maxDistance: MAX_RANGE });
  if (!hit) {
    player.onScreenDisplay.setActionBar("§7Too far away — point at a block!");
    return;
  }

  lastZapTick.set(player.id, now);

  const target = {
    x: hit.block.location.x + 0.5,
    y: hit.block.location.y + 1,
    z: hit.block.location.z + 0.5,
  };
  player.dimension.spawnEntity("minecraft:lightning_bolt", target);
  player.onScreenDisplay.setActionBar("§e⚡ Zap!");
});
