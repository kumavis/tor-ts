# Tasty Treats — real-life pixel foods for Minecraft Bedrock

A Minecraft Bedrock Add-On adding eight real-life foods that vanilla doesn't
have, all in vanilla-matching 16x16 pixel art. Works on iPad, phones,
consoles, and Windows (Bedrock Edition, 1.21+).

## The foods

Bowl foods use a real `minecraft:bowl` in the recipe and give the empty bowl
back when you finish eating, exactly like mushroom stew (`using_converts_to`).

| Food | Type | Hunger | Recipe (crafting table) | Extra |
|---|---|---|---|---|
| §eRamen | bowl | 8 | bowl + 2 wheat + cooked chicken | 30s Fire Resistance ("Warm and cozy!") |
| §fCereal | bowl | 5 | bowl + milk bucket + 2 wheat | — |
| §bIce Cream Sundae | bowl | 4 | bowl + milk bucket + snowball + sugar | 3s "Brain freeze!!" slowness; edible when full |
| §cPizza Slice | hand | 6 | 2 wheat + milk bucket + sweet berries → 4 | — |
| §6Taco | hand | 6 | wheat + cooked beef + sweet berries → 2 | — |
| §dDonut | hand | 3 | 3 wheat + sugar + cocoa beans → 3 | edible when full |
| §6Cheeseburger | hand | 8 | bread / cooked beef / bread (shaped) | — |
| §dRainbow Candy | hand | 2 | 2 sugar + glow berries → 4 | 30s Speed II + Jump Boost II; edible when full |
| §aSushi | hand | 5 | salmon + dried kelp + wheat → 2 | placeable on a cutting board |
| §dBerry Smoothie | drink | 4 | blender: bottle + 2 sweet berries + snowball | 5s Regeneration II; returns the bottle; drinkable when full |
| §aMelon Smoothie | drink | 4 | blender: bottle + 2 melon slices + snowball | 30s Absorption II |
| §6Choco Smoothie | drink | 4 | blender: bottle + 2 cocoa beans + snowball | 30s Strength |
| §eGlow Smoothie | drink | 4 | blender: bottle + 2 glow berries + snowball | 60s Night Vision |
| §fMilkshake | drink | 6 | blender: bottle + ice cream sundae + sugar | 30s Resistance |
| §fChef's Hat | wear | — | white wool over paper, hat-shaped | wearable 3D hat (head slot) |

(Sweet berries stand in for tomatoes; milk stands in for cheese; wheat for rice.)

## The smoothie bar

Craft a **Blender** (3 glass in a jar shape over 3 iron ingots) and place
it. Tapping it opens a real crafting menu titled "Blender" — same UI as a
crafting table, but it's the only place drink recipes appear: the four
smoothies and the milkshake are tagged `blender` and cannot be made at a
regular crafting table. All drinks use the drink animation and return
their bottle when finished. Mine the blender to pick it back up.
(`minecraft:crafting_table` block component + recipe `tags: ["blender"]`.)

## Placing food in the world

Foods served on something can be set down as decoration: **sneak, then use
the food on a block** (on iPad: toggle sneak, then tap-and-hold on the
ground). Ramen, cereal, and ice cream place as a 3D bowl; sushi places as a
cutting board with nigiri and a maki roll. Normal (non-sneak) use still
eats. Mine the placed dish to get the food item back.

The blocks use custom geometry (`tasty_treats_rp/models/blocks/`) with
32x32 texture atlases, and the placement logic is the `itemUseOn` handler
in `scripts/main.js`.

All recipes are shapeless except the cheeseburger. Or with cheats on:
`/give @s demo:ramen` etc. — ids are `demo:ramen`, `demo:cereal`,
`demo:ice_cream`, `demo:pizza_slice`, `demo:taco`, `demo:donut`,
`demo:cheeseburger`, `demo:rainbow_candy`. They also appear in the creative
inventory under food.

## What's in it

```
tasty_treats_bp/                    Behavior pack (game logic)
  manifest.json                     Pack identity + script module + RP dependency
  items/*.json                      One data-driven food item per file
  recipes/*.json                    One recipe per food
  blocks/*.json                     Placeable dish blocks (custom geometry)
  loot_tables/blocks/*.json         Mining a dish drops its food back
  scripts/main.js                   Effects table + sneak-to-place handler
tasty_treats_rp/                    Resource pack (visuals)
  attachables/chefs_hat.json        Worn-on-head model binding
  models/entity/chefs_hat.geo.json  3D hat geometry (head bone)
  models/blocks/food_blocks.geo.json  3D bowl + sushi board geometry
  textures/items/*.png              16x16 pixel-art sprites
  textures/item_texture.json        Maps icon names to sprites
TastyTreats.mcaddon                 The shippable file (zip of both packs)
```

## Install on an iPad

1. Send `TastyTreats.mcaddon` to the device (AirDrop, Messages, Files…).
2. Tap it → "Open in Minecraft" → both packs import.
3. Create or edit a world → **Behavior Packs** → activate
   *Tasty Treats (Behavior)* (the resource pack follows automatically).

Eat with the normal gesture (tap-and-hold on iPad).

No "Beta APIs" experiment needed — the script uses only the stable
`@minecraft/server` 1.9.0 API.

## Rebuild after editing

```sh
cd minecraft/tasty-treats
rm -f TastyTreats.mcaddon
zip -r TastyTreats.mcaddon tasty_treats_bp tasty_treats_rp
```

Bump the `version` in both manifests when you ship changes so devices that
imported an older copy pick up the update (this pack is at 1.6.0).

## Ideas to extend it

- More foods: add an item JSON + recipe + sprite, and (optionally) an entry
  in the `FOOD_EFFECTS` table in `scripts/main.js`.
- Cooking steps: make pizza require a furnace via `minecraft:recipe_furnace`.
- Particles/sounds when effects trigger (`spawnParticle`, `playSound`).
- Eat-from-the-dish: an `on_player_interact` block event that feeds the
  player and swaps the block back to air.
- All pixel art is generated by `tools/make_art.py` — edit the character
  maps and rerun `python3 tools/make_art.py .` to restyle everything.
