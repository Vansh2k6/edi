---
name: Privacy Vault Guard
description: The Quiet Institution — a formal, light-first design system for personal-data sovereignty
colors:
  ink: "#132B50"
  ink-soft: "#46618F"
  ink-faint: "#7A90B8"
  primary: "#1D4ED8"
  primary-deep: "#1E40AF"
  primary-wash: "#EAF1FB"
  page-white: "#FDFEFF"
  card-white: "#FFFFFF"
  hairline: "#C7D8F0"
  hairline-soft: "#E2EAF6"
  allow-deep: "#1B7F4B"
  allow-tint: "#E7F5EC"
  warn-deep: "#9A6B15"
  warn-tint: "#FBF3E1"
  block-deep: "#B3372E"
  block-tint: "#FBEAE8"
typography:
  display:
    fontFamily: "Source Serif 4, Georgia, 'Times New Roman', serif"
    fontSize: "clamp(2rem, 4vw, 2.75rem)"
    fontWeight: 600
    lineHeight: 1.15
    letterSpacing: "normal"
  headline:
    fontFamily: "Source Serif 4, Georgia, serif"
    fontSize: "1.375rem"
    fontWeight: 600
    lineHeight: 1.3
    letterSpacing: "normal"
  title:
    fontFamily: "Inter, 'Segoe UI', system-ui, sans-serif"
    fontSize: "1rem"
    fontWeight: 600
    lineHeight: 1.4
    letterSpacing: "normal"
  body:
    fontFamily: "Inter, 'Segoe UI', system-ui, sans-serif"
    fontSize: "0.9375rem"
    fontWeight: 400
    lineHeight: 1.6
    letterSpacing: "normal"
  label:
    fontFamily: "Inter, 'Segoe UI', system-ui, sans-serif"
    fontSize: "0.6875rem"
    fontWeight: 600
    lineHeight: 1.2
    letterSpacing: "0.08em"
  mono:
    fontFamily: "JetBrains Mono, Consolas, 'Courier New', monospace"
    fontSize: "0.8125rem"
    fontWeight: 400
    lineHeight: 1.5
    letterSpacing: "normal"
rounded:
  sm: "8px"
  md: "12px"
  lg: "16px"
  xl: "24px"
  pill: "999px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "16px"
  lg: "24px"
  xl: "32px"
  xxl: "48px"
components:
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.card-white}"
    rounded: "{rounded.md}"
    padding: "10px 20px"
    typography: "{typography.title}"
  button-primary-hover:
    backgroundColor: "{colors.primary-deep}"
    textColor: "{colors.card-white}"
    rounded: "{rounded.md}"
    padding: "10px 20px"
  button-secondary:
    backgroundColor: "{colors.card-white}"
    textColor: "{colors.primary}"
    rounded: "{rounded.md}"
    padding: "10px 20px"
  card:
    backgroundColor: "{colors.card-white}"
    textColor: "{colors.ink}"
    rounded: "{rounded.lg}"
    padding: "{spacing.lg}"
  input:
    backgroundColor: "{colors.card-white}"
    textColor: "{colors.ink}"
    rounded: "{rounded.md}"
    padding: "10px 14px"
  status-pill-block:
    backgroundColor: "{colors.block-tint}"
    textColor: "{colors.block-deep}"
    rounded: "{rounded.pill}"
    padding: "4px 12px"
  decision-overlay:
    backgroundColor: "{colors.card-white}"
    textColor: "{colors.ink}"
    rounded: "{rounded.xl}"
    padding: "{spacing.lg}"
---

# Design System: Privacy Vault Guard

## Overview

**Creative North Star: "The Quiet Institution"**

This system treats the personal data vault the way a private bank treats its interior: calm, official, and softly lit. Authority comes from *order*, not weight — a serif that sets the terms, hairline rules that hold the structure, generous white space that signals nothing is hidden. The product handles the most sensitive decisions a person makes online; the interface must feel like the one room where nothing is in a hurry.

The world is **light without exception**. Every surface is white or a pale blue wash; the deepest blue in the system is text and small accents, never a background. Depth is conveyed by soft, blue-cast shadows and one deliberate formal device: the **layered document planes** — a static, three-layer arrangement of softly-lit white sheets with a light blue wash resting behind the content, like formal files on a desk photographed for an annual report. The planes never move: no scroll animation, no parallax, no drift. A background that moves is a background that distracts from a decision.

Expression is spent in exactly three places — the serif voice, the document planes, and the pill-shaped decision states — so that everywhere else the interface can simply be clear.

**Key Characteristics:**
- Light-first: white canvases, pale blue washes, no dark surfaces anywhere
- Serif for voice (headings), sans for service (everything else), mono for the machine's record
- Softened geometry: no 90-degree corners; smallest radius is 8px, panels reach 24px
- Static formal 3D: layered document planes behind content, fixed forever
- Motion limited to 120–180 ms opacity and 1px lifts; fully removed under reduced-motion
- Blue-cast shadows only; grey and black shadows are out of system

## Colors

The palette is a white page, a blue ink, and four quiet tints. Blue is the institution; white is the document it stamps.

### Primary
- **Decree Blue** (#1D4ED8): The institution's seal. Primary actions, active navigation, focus rings, links, and the strongest data emphasis. Never a large background fill.
- **Decree Deep** (#1E40AF): Hover and pressed states of Decree Blue; also small-text emphasis where #1D4ED8 lacks contrast at small sizes on tinted surfaces.

### Neutral
- **Contract Ink** (#132B50): All primary text. A blue-black that keeps every line of copy inside the institution's hue family. Never pure black (#000000).
- **Clerk's Slate** (#46618F): Secondary text — descriptions, helper copy, inactive labels.
- **Faded Registry** (#7A90B8): Tertiary metadata — timestamps, counts, disabled text.
- **Page White** (#FDFEFF): The page canvas. A breath of cool blue keeps pure white surfaces visible against it.
- **Card White** (#FFFFFF): Cards, panels, the decision overlay, inputs.
- **Hairline Blue** (#C7D8F0): Primary 1px borders — input strokes, dividers that must hold.
- **Hairline Soft** (#E2EAF6): Secondary 1px borders — card edges, table rules, quiet dividers.
- **Wash Blue** (#EAF1FB): Tinted backgrounds — hover fills, selected rows, the document-plane wash, code-block grounds.

### Semantic (decision states)
- **Blocked** — Deep (#B3372E) on Tint (#FBEAE8)
- **Approval Required** — Decree Blue on Wash Blue (shares the primary pair)
- **Warning** — Deep (#9A6B15) on Tint (#FBF3E1)
- **Allowed** — Deep (#1B7F4B) on Tint (#E7F5EC)

### Named Rules
**The White Page Rule.** No dark surfaces exist in this system. The darkest background permitted is Wash Blue (#EAF1FB). If a design feels like it needs a dark panel, it needs hierarchy instead.

**The Seal Rule.** Decree Blue behaves like an official seal: it appears on primary actions, active states, focus, and key data — occupying well under 10% of any screen. Large blue fills dissolve its authority.

## Typography

**Display Font:** Source Serif 4 (with Georgia, then Times New Roman)
**Body Font:** Inter (with Segoe UI, then system-ui)
**Label Font:** Inter, uppercase, tracked
**Registry Font:** JetBrains Mono (with Consolas, then Courier New)

**Character:** A formal document spoken by a calm machine. The serif carries ceremony — titles, decision verdicts, the owner's name. The sans does the service work — bodies, labels, controls. The mono face is the audit trail: every identifier, hash, policy version, and timestamp renders in it, because machine output should look like machine record, not like prose.

### Hierarchy
- **Display** (Source Serif 4, 600, clamp(2rem → 2.75rem), 1.15): Page titles and the vault's name. One per page.
- **Headline** (Source Serif 4, 600, 1.375rem, 1.3): Section headings and the decision overlay's verdict line.
- **Title** (Inter, 600, 1rem, 1.4): Card titles, button text, table column heads.
- **Body** (Inter, 400, 0.9375rem, 1.6): All running text. Prose measures at 65–75ch.
- **Label** (Inter, 600, 0.6875rem, 0.08em tracking, UPPERCASE): Field labels, eyebrows, status words. The tracking does the ceremonial work — never also bold the surrounding sentence.
- **Registry** (JetBrains Mono, 400, 0.8125rem, 1.5): `decision_id`, `policy_version`, hashes, hex colors shown in settings, timestamps.

### Named Rules
**The Letterhead Rule.** Serif is reserved for headings and verdicts. It never sets body copy, buttons, or labels — a letterhead is not a paragraph.

**The Registry Rule.** Any value a user might quote back to support — an id, a version, a hash — renders in JetBrains Mono, never in Inter. If it is copyable, it is mono.

## Layout

An 8px rhythm governs everything: 4 / 8 / 16 / 24 / 32 / 48. Cards pad at 24px; related controls separate by 8px; sections breathe at 48px. Prose holds a 65–75ch measure; dashboards use a 12-column grid with 24px gutters and a max content width of 1200px.

The **decision overlay** (the product's signature surface) fixes to the bottom-right: max-width 380px, 24px outer margin, stacking above page content. It never covers the full viewport — the owner keeps their page; the institution keeps its corner.

The **document planes** occupy the background layer behind every page: three static sheets at increasing scale and decreasing opacity (100% / 60% / 35%), rotated between −2° and 1.5°, offset toward the upper right, softened with a 40–60px blur on their shadows and a Wash Blue radial wash behind them. They sit at `position: fixed`, `pointer-events: none`, `z-index: -1`, and are rendered once — they do not respond to scroll, pointer, or time. On screens under 768px the layers reduce to two.

## Elevation & Depth

Depth is paper resting on paper. Every shadow is **blue-cast** — derived from Contract Ink, never from grey or black — and diffuse: short contact shadow plus a long, quiet one.

### Shadow Vocabulary
- **Rest** (`0 1px 2px rgba(19,43,80,0.05), 0 4px 16px rgba(31,90,184,0.08)`): Cards and inputs at rest.
- **Raised** (`0 2px 4px rgba(19,43,80,0.06), 0 8px 24px rgba(31,90,184,0.12)`): Hover on interactive cards; open dropdowns.
- **Overlay** (`0 24px 64px rgba(19,43,80,0.18)`): The decision overlay and modals only.
- **Plane** (`0 40px 80px rgba(31,90,184,0.10)`): The document planes — the largest, quietest shadow in the system.

### Named Rules
**The Blue Shadow Rule.** Every shadow in the system carries blue in its rgba. A grey or black shadow reads as dirt on the page; a blue shadow reads as light.

## Shapes

Nothing in this system meets the screen at a right angle. The radius ladder is 8px (chips, small tags) → 12px (inputs, buttons) → 16px (cards) → 24px (overlay, modals) → full pill (status states). Borders are 1px hairlines in the two blue-greys; a component either has a hairline or a shadow — never both at full strength. Media and code blocks clip at the radius of their container; a rounded card never contains a square image corner.

### Named Rules
**The No Right Angle Rule.** If a corner computes to 0px, it is a defect. The smallest legal radius is 8px.

## Components

### Buttons
- **Shape:** 12px radius, 10px × 20px padding, Title typography.
- **Primary:** Decree Blue fill, Card White text. Hover: Decree Deep + Raised shadow. This is the only filled-blue element on a screen.
- **Secondary:** Card White fill, 1px Hairline Blue stroke, Decree Blue text. Hover: Wash Blue fill.
- **Deliberate actions** (Force Allow, revoke device): Secondary treatment with the semantic deep color as text — the weight comes from placement and confirmation, never from a loud fill.
- **Ghost:** No fill, no stroke, Clerk's Slate text; Wash Blue on hover. Tertiary actions only.
- **Focus:** 3px ring `rgba(29,78,216,0.35)` with 2px offset, on every interactive element.
- **Motion:** background-color and shadow transition 150ms ease; no transform beyond a 1px lift on Raised.

### Status Pills
- **Style:** Full pill radius, 4px × 12px padding, Label typography in the semantic **deep** color on its **tint**.
- **State:** Exactly the four decision states. A pill never carries a custom color; if a fifth state appears, the system grows a pair first.

### Cards
- **Corner Style:** 16px.
- **Background:** Card White on Page White; never Wash-on-Wash.
- **Shadow Strategy:** Rest at rest, Raised on hover if clickable.
- **Border:** 1px Hairline Soft.
- **Internal Padding:** 24px.

### Inputs
- **Style:** Card White ground, 1px Hairline Blue stroke, 12px radius, 10px × 14px padding.
- **Focus:** stroke becomes Decree Blue; ring `rgba(29,78,216,0.25)`, 3px.
- **Error:** Block tint ground with a 1px Block deep stroke; the message below sets Body size in Block deep. Errors never shake or flash.

### Decision Overlay (signature component)
Card White, 24px radius, Overlay shadow, fixed bottom-right at 380px. Structure top to bottom: the state pill; a Headline serif verdict ("ACCESS BLOCKED"); the site in Registry mono; requested fields as a Body list; the **why** reasons with Hairline Soft dividers; the enforcement note in Clerk's Slate italic when a block could not be enforced; then actions — "Keep blocked" as Ghost, "Force Allow (this decision only)" as the deliberate outlined action. A critical security block renders no Force Allow control at all, and its verdict line sits in Block deep.

### Document-Plane Background (signature component)
Three fixed, static layers behind all content, rendered once at load:

```css
.pv-planes { position: fixed; inset: 0; z-index: -1; pointer-events: none;
  background:
    radial-gradient(120% 90% at 85% -10%, #EAF1FB 0%, rgba(234,241,251,0) 60%),
    #FDFEFF; }
.pv-plane { position: absolute; border-radius: 24px;
  background: linear-gradient(160deg, #FFFFFF 0%, #F4F8FE 100%); }
.pv-plane--near { top: -6%; right: -4%; width: 62vw; height: 70vh;
  transform: rotate(-2deg); opacity: 1;
  box-shadow: 0 40px 80px rgba(31,90,184,0.10), 0 2px 0 rgba(199,216,240,0.6); }
.pv-plane--mid  { top: 18%; right: 22%; width: 48vw; height: 60vh;
  transform: rotate(1.5deg); opacity: 0.6;
  box-shadow: 0 40px 80px rgba(31,90,184,0.07); }
.pv-plane--far  { top: 44%; right: -8%; width: 40vw; height: 52vh;
  transform: rotate(-1deg); opacity: 0.35;
  box-shadow: 0 40px 80px rgba(31,90,184,0.05); }
@media (max-width: 767px) { .pv-plane--far { display: none; } }
```

The planes carry no animation, no transition, and no scroll listener — their stillness *is* the formality.

## Do's and Don'ts

### Do:
- **Do** keep every background light: Page White, Card White, or Wash Blue are the only legal grounds.
- **Do** use Source Serif 4 for headings and verdicts, Inter for everything operational, JetBrains Mono for every quotable identifier.
- **Do** round everything — 8px minimum, 24px for panels — and pair a hairline *or* a shadow, not both at full strength.
- **Do** keep motion to 150ms color/shadow transitions and 1px lifts, and remove all of it under `prefers-reduced-motion`.
- **Do** render the document planes once, fixed, at `pointer-events: none`, with two layers on mobile.
- **Do** express decision states exclusively through the four deep-on-tint pill pairs.

### Don't:
- **Don't** introduce a dark surface, a near-black panel, or grey/black shadows — depth comes from blue-cast light.
- **Don't** animate the background, attach scroll or parallax to it, or blur content behind glass panels; the planes are architecture, not spectacle.
- **Don't** use sharp corners anywhere — a 0px radius is a defect, not a style.
- **Don't** fill large areas with Decree Blue; the seal loses its authority when it becomes wallpaper.
- **Don't** set identifiers, hashes, or policy versions in Inter — if a user might quote it, it belongs to the Registry (mono).
- **Don't** supersede this system's decisions in surface code. The incumbent overlay's dark navy ground (#0f172a) and 12px-only world are replaced by this document.
