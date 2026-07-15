import { world } from "@minecraft/server";

// ---------------------------------------------------------------- effects
// Granted when a food finishes being eaten. Durations are in ticks
// (20 ticks = 1 second). Add a new food here + an item JSON and you're done.
const FOOD_EFFECTS = {
  "demo:rainbow_candy": {
    effects: [
      { effect: "speed", duration: 600, amplifier: 1 },
      { effect: "jump_boost", duration: 600, amplifier: 1 },
    ],
    message: "§dSugar rush! Speed + Jump Boost!",
  },
  "demo:ramen": {
    effects: [{ effect: "fire_resistance", duration: 600, amplifier: 0 }],
    message: "§6Warm and cozy! Fire Resistance!",
  },
  "demo:ice_cream": {
    effects: [{ effect: "slowness", duration: 60, amplifier: 0 }],
    message: "§bBrain freeze!!",
  },
  "demo:smoothie": {
    effects: [{ effect: "regeneration", duration: 100, amplifier: 1 }],
    message: "§dBerry blast! Regeneration!",
  },
};

world.afterEvents.itemCompleteUse.subscribe((event) => {
  const entry = FOOD_EFFECTS[event.itemStack?.typeId];
  if (!entry) return;

  for (const { effect, duration, amplifier } of entry.effects) {
    event.source.addEffect(effect, duration, { amplifier });
  }
  event.source.onScreenDisplay.setActionBar(entry.message);
});

// -------------------------------------------------------------- placement
// Foods served on something (bowl, board) can be set down in the world:
// sneak + use on a block places the dish; mining it drops the food back.
const PLACEABLE = {
  "demo:ramen": "demo:ramen_bowl",
  "demo:cereal": "demo:cereal_bowl",
  "demo:ice_cream": "demo:ice_cream_bowl",
  "demo:sushi": "demo:sushi_board",
};

const FACE_OFFSETS = {
  Up: { x: 0, y: 1, z: 0 },
  Down: { x: 0, y: -1, z: 0 },
  North: { x: 0, y: 0, z: -1 },
  South: { x: 0, y: 0, z: 1 },
  West: { x: -1, y: 0, z: 0 },
  East: { x: 1, y: 0, z: 0 },
};

world.afterEvents.itemUseOn.subscribe((event) => {
  const blockId = PLACEABLE[event.itemStack?.typeId];
  if (!blockId) return;

  const player = event.source;
  if (!player.isSneaking) return; // normal use still eats

  const offset = FACE_OFFSETS[event.blockFace];
  if (!offset) return;

  const loc = event.block.location;
  const target = event.block.dimension.getBlock({
    x: loc.x + offset.x,
    y: loc.y + offset.y,
    z: loc.z + offset.z,
  });
  if (!target?.isAir) return;

  target.setType(blockId);
  player.playSound("dig.wood", { location: target.location });

  // Consume one item, except in creative (matching vanilla block placement)
  try {
    if (player.getGameMode() === "creative") return;
  } catch {
    // getGameMode unavailable on very old engines; fall through and consume
  }
  const container = player.getComponent("inventory")?.container;
  const held = container?.getItem(player.selectedSlot);
  if (!held || held.typeId !== event.itemStack.typeId) return;
  if (held.amount > 1) {
    held.amount -= 1;
    container.setItem(player.selectedSlot, held);
  } else {
    container.setItem(player.selectedSlot, undefined);
  }
});
