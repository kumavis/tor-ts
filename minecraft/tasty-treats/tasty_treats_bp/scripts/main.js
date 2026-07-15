import { world, ItemStack } from "@minecraft/server";

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
  "demo:melon_smoothie": {
    effects: [{ effect: "absorption", duration: 600, amplifier: 1 }],
    message: "§aMelon shield! Absorption!",
  },
  "demo:choco_smoothie": {
    effects: [{ effect: "strength", duration: 600, amplifier: 0 }],
    message: "§6Choco power! Strength!",
  },
  "demo:glow_smoothie": {
    effects: [{ effect: "night_vision", duration: 1200, amplifier: 0 }],
    message: "§eGlow up! Night Vision!",
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

// ---------------------------------------------------------------- blender
// Tap the blender block with a fruit in hand (glass bottle somewhere in
// your inventory) and it blends a smoothie on the spot.
const BLENDER_RECIPES = {
  "minecraft:sweet_berries": "demo:smoothie",
  "minecraft:melon_slice": "demo:melon_smoothie",
  "minecraft:cocoa_beans": "demo:choco_smoothie",
  "minecraft:glow_berries": "demo:glow_smoothie",
};

function takeOne(container, slot) {
  const stack = container.getItem(slot);
  if (!stack) return;
  if (stack.amount > 1) {
    stack.amount -= 1;
    container.setItem(slot, stack);
  } else {
    container.setItem(slot, undefined);
  }
}

world.afterEvents.itemUseOn.subscribe((event) => {
  if (event.block.typeId !== "demo:blender") return;
  const result = BLENDER_RECIPES[event.itemStack?.typeId];
  if (!result) return;

  const player = event.source;
  const container = player.getComponent("inventory")?.container;
  if (!container) return;

  let creative = false;
  try {
    creative = player.getGameMode() === "creative";
  } catch {}

  if (!creative) {
    let bottleSlot = -1;
    for (let i = 0; i < container.size; i++) {
      if (container.getItem(i)?.typeId === "minecraft:glass_bottle") {
        bottleSlot = i;
        break;
      }
    }
    if (bottleSlot < 0) {
      player.onScreenDisplay.setActionBar("§7The blender needs a glass bottle!");
      return;
    }
    takeOne(container, bottleSlot);
    if (container.getItem(player.selectedSlot)?.typeId === event.itemStack.typeId) {
      takeOne(container, player.selectedSlot);
    }
  }

  const leftover = container.addItem(new ItemStack(result, 1));
  if (leftover) {
    const loc = event.block.location;
    player.dimension.spawnItem(leftover, { x: loc.x + 0.5, y: loc.y + 1, z: loc.z + 0.5 });
  }
  player.playSound("random.click");
  player.playSound("random.pop");
  player.onScreenDisplay.setActionBar("§bWhirrrr! Smoothie ready!");
});

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
