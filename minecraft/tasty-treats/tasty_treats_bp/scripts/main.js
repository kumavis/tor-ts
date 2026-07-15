import { world } from "@minecraft/server";

// Effects granted when a food finishes being eaten. Durations are in ticks
// (20 ticks = 1 second), so 600 = 30 seconds of sugar-rush parkour powers.
const FOOD_EFFECTS = {
  "demo:rainbow_candy": [
    { effect: "speed", duration: 600, amplifier: 1 },
    { effect: "jump_boost", duration: 600, amplifier: 1 },
  ],
};

world.afterEvents.itemCompleteUse.subscribe((event) => {
  const effects = FOOD_EFFECTS[event.itemStack?.typeId];
  if (!effects) return;

  for (const { effect, duration, amplifier } of effects) {
    event.source.addEffect(effect, duration, { amplifier });
  }
  event.source.onScreenDisplay.setActionBar("§dSugar rush! Speed + Jump Boost!");
});
