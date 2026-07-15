import { world } from "@minecraft/server";

// Effects granted when a food finishes being eaten. Durations are in ticks
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
};

world.afterEvents.itemCompleteUse.subscribe((event) => {
  const entry = FOOD_EFFECTS[event.itemStack?.typeId];
  if (!entry) return;

  for (const { effect, duration, amplifier } of entry.effects) {
    event.source.addEffect(effect, duration, { amplifier });
  }
  event.source.onScreenDisplay.setActionBar(entry.message);
});
