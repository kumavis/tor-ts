# Tasty Treats — example food Add-On

A Minecraft Bedrock Add-On adding two custom foods. Works on iPad, phones,
consoles, and Windows (Bedrock Edition, 1.21+).

- **§6Cheeseburger** — a hearty meal (8 hunger, high saturation). Defined
  entirely in JSON — no code at all.
- **§dRainbow Candy** — a quick snack you can eat even when full. When the
  eating animation finishes, a script grants 30 seconds of Speed II +
  Jump Boost II ("sugar rush").

## What's in it

```
tasty_treats_bp/                    Behavior pack (game logic)
  manifest.json                     Pack identity + script module + RP dependency
  items/cheeseburger.json           Pure-JSON food: minecraft:food component
  items/rainbow_candy.json          Food JSON; effects come from the script
  recipes/cheeseburger.json         Shaped: bread / cooked beef / bread
  recipes/rainbow_candy.json        Shapeless: 2 sugar + glow berries -> 4 candy
  scripts/main.js                   itemCompleteUse -> addEffect (speed, jump)
tasty_treats_rp/                    Resource pack (visuals)
  textures/items/*.png              16x16 sprites
  textures/item_texture.json        Maps icon names to sprites
TastyTreats.mcaddon                 The shippable file (zip of both packs)
```

## Install on an iPad

1. Send `TastyTreats.mcaddon` to the device (AirDrop, Messages, Files…).
2. Tap it → "Open in Minecraft" → both packs import.
3. Create or edit a world → **Behavior Packs** → activate
   *Tasty Treats (Behavior)* (the resource pack follows automatically).

## Getting the foods in game

- Craft them: cheeseburger is bread / cooked beef / bread stacked vertically
  in a crafting table; candy is 2 sugar + 1 glow berries anywhere in the grid
  (makes 4).
- Or with cheats on: `/give @s demo:cheeseburger` and `/give @s demo:rainbow_candy`.
- They also appear in the creative inventory under food.

Eat with the normal gesture (tap-and-hold on iPad). The candy's
`can_always_eat: true` means it works even with a full hunger bar.

No "Beta APIs" experiment needed — the script uses only the stable
`@minecraft/server` 1.9.0 API.

## Rebuild after editing

```sh
cd minecraft/tasty-treats
rm -f TastyTreats.mcaddon
zip -r TastyTreats.mcaddon tasty_treats_bp tasty_treats_rp
```

Bump the `version` in both manifests when you ship changes so devices that
imported an older copy pick up the update.

## Ideas to extend it

- More foods: the FOOD_EFFECTS table in `scripts/main.js` is built for it —
  add an item JSON + a table entry and you're done.
- A downside food: "Mystery Meat" with a chance of nausea (`Math.random()`
  isn't the issue here — scripts can use it — just add a negative effect).
- Cooking: make the burger require a furnace step via a `recipe_furnace`.
- Particles/sounds on the sugar rush (`spawnParticle`, `playSound`).
