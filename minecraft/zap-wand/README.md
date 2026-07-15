# Zap Wand — example Bedrock Add-On

A minimal but complete Minecraft Bedrock Add-On: a craftable **Zap Wand** that
strikes lightning wherever you point it. Works on iPad, phones, consoles, and
Windows (Bedrock Edition, 1.21+).

## What's in it

```
zap_wand_bp/                 Behavior pack (game logic)
  manifest.json              Pack identity + script module + dependency on the RP
  items/zap_wand.json        Defines the demo:zap_wand item (data-driven, no code)
  recipes/zap_wand.json      Crafting recipe: glowstone dust + 2 sticks, diagonal
  scripts/main.js            Script API: itemUse event -> raycast -> lightning bolt
zap_wand_rp/                 Resource pack (visuals)
  textures/items/zap_wand.png    16x16 item sprite
  textures/item_texture.json     Maps the "zap_wand" icon name to the sprite
ZapWand.mcaddon              The shippable file (zip of both packs)
```

## Install on an iPad

1. Send `ZapWand.mcaddon` to the device (AirDrop, Messages, Files…).
2. Tap it → "Open in Minecraft" → it imports both packs.
3. Create or edit a world → **Behavior Packs** → activate *Zap Wand (Behavior)*
   (the resource pack activates automatically as a dependency).
4. In game: craft the wand (glowstone dust top-right, two sticks diagonally
   below it) or `/give @s demo:zap_wand`, then tap-and-hold / right-click
   while aiming at a block. ⚡

No "Beta APIs" experiment needed — the script uses only the stable
`@minecraft/server` 1.9.0 API.

## Rebuild after editing

```sh
cd minecraft/zap-wand
rm -f ZapWand.mcaddon
zip -r ZapWand.mcaddon zap_wand_bp zap_wand_rp
```

If you change pack contents in a meaningful way, bump the `version` in both
manifests so devices that already imported an older copy pick up the update.

## Ideas to extend it

- Charge levels: hold sneak to charge, bigger boom (listen to `itemStartUse` /
  `itemStopUse` and measure ticks held).
- A second item that launches the *player* (grappling wand: `applyKnockback`).
- Custom sounds on zap (`playSound` + a `sounds/sound_definitions.json` in the RP).
- Port the script to TypeScript with Microsoft's `minecraft-scripting-samples`
  starter and esbuild — the API objects are identical, you just get types.
