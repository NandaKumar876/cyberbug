# Console UX research notes

This prototype should feel like a security-operational workspace, not a reporting dashboard. The interface therefore prioritizes a decision and its evidence before secondary aggregate metrics.

## Research applied

- [Material Design 3](https://m3.material.io/) treats design as an adaptable system of tokens and components rather than a fixed visual theme. CyberBug uses semantic surface, outline, primary-container, and state tokens so light and dark themes retain meaning without duplicating components.
- [Material interaction states](https://m3.material.io/foundations/interaction/states/overview) calls for consistent enabled, hover, pressed, and focused states. Console navigation, controls, rows, and buttons have keyboard focus treatment and clear selected/active states.
- Material's [canonical layouts](https://m3.material.io/foundations/layout/canonical-examples/overview) describe distinct compact, medium, and expanded arrangements. The console uses a desktop rail, an off-canvas compact navigation drawer, and single-column investigation panels when horizontal space falls away.
- The [USWDS table guidance](https://designsystem.digital.gov/components/table/) supports semantic header rows, short labels, predictable values, monospace numeric data, and either scrolling or stacking at narrow widths. The investigation table keeps column semantics and becomes horizontally scrollable on small screens instead of compressing values into illegibility.

## Product decisions

1. The overview starts with a **priority decision**. It names the contained session, why action was permitted, and links to evidence. Aggregate counts become supporting posture signals rather than four visually equal tiles.
2. The identity screen shows parallel contexts. It makes it clear that one contained context does not define the person or their healthy manager-device session.
3. Deception pages repeat the response gate: high risk alone cannot expose a decoy. Intent and absence of a verified override are visually present in the workflow.
4. Sensitive wording stays precise. The UI says `probable intent`, `evidence`, and `behavioral context`, never claims a model has identified a physical attacker.
