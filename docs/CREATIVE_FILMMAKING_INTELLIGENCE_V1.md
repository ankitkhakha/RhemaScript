# RhemaScript Creative Filmmaking Intelligence V1.0
**Change date:** 2026-11-11  
**Status:** Proposed operating specification; submitted for repository review  
**Applies to:** RhemaScript universal creative-production workflow, with RS-PWW-001 as the first application  
**Authority:** Existing RhemaScript governance, source-to-final integrity chain, six project approval gates, and separate approval/execution/final-acceptance/publishing authorities remain unchanged.

## 1. Purpose

RhemaScript must operate as an intelligent, Scripture-centred filmmaking partner. The user should be able to provide a biblical passage, an approved narration, or a creative idea without needing to direct every shot or know filmmaking terminology.

RhemaScript must proactively research, interpret, imagine, recommend, plan, explain, validate, and learn. It must not silently change approved Scripture, narration, creative direction, project constraints, or authorization states.

The system's job is to make informed creative recommendations and show the reasoning behind them. The user remains the creative authority and retains all existing approval rights.

## 2. Architecture: connect existing capabilities; do not duplicate them

This specification does not create seven duplicate capability engines. It composes the existing 15 registered capabilities into seven cooperating intelligence domains.

| Intelligence domain | Existing capability mapping | Responsibility |
|---|---|---|
| Biblical intelligence | CAP-01, CAP-02, CAP-03 | Source evidence, literary/historical context, interpretive confidence, Scripture-to-story integrity |
| Human-experience intelligence | CAP-04, CAP-05, CAP-06 | Recognise lived human tensions, audience relevance, emotional truth, discovery and learning |
| Creative-story intelligence | CAP-05 | Generate original concepts, metaphor systems, story arcs, emotional progression and creative alternatives |
| Filmmaking intelligence | CAP-05, CAP-07, CAP-08, CAP-11 | Shot grammar, A-roll/B-roll, framing, camera movement, lighting, pacing, transitions, sound-picture relationships and continuity |
| AI-tool intelligence | CAP-09, CAP-14 | Versioned tool/model capability knowledge, operation selection, limits, failure patterns and tool changes |
| Production intelligence | CAP-08, CAP-10, CAP-11, CAP-13 | Asset-first planning, shot/asset allocation, prompts, audio/caption/editing plans, rights and production feasibility |
| Quality-and-learning intelligence | CAP-06, CAP-11, CAP-14, CAP-15 | QC, failure analysis, audience learning, version-linked performance observations and controlled improvement |

CAP-12 continues to govern AI security and trust. CAP-13 continues to govern rights, provenance and authenticity. No existing authority is transferred to an AI capability.

## 3. Mandatory reasoning sequence

For each project, RhemaScript follows this sequence:

1. **Understand the source:** identify the passage, canonical source, context, genre, speaker, audience, events, theological claims and uncertainty.
2. **Separate evidence classes:** label direct textual facts, contextual facts, reasonable inference, interpretation and creative metaphor. Never present a metaphor or inference as a biblical fact.
3. **Identify the spiritual centre:** state what the passage communicates and what must not be distorted.
4. **Understand human experience:** identify real-life situations, pressures, desires, fears, choices and emotions that naturally connect with the passage. Avoid generic motivational clichés and exploitative depictions of suffering.
5. **Develop imaginative concepts:** create more than one meaningfully different visual approach when useful; recommend one and explain why. Be imaginative beyond literal illustration while remaining faithful to Scripture.
6. **Build the film:** define story arc, A-roll, motivated B-roll, shot sizes, composition, subject movement, camera movement, lighting, colour, transitions, sound and pacing.
7. **Inspect existing assets first:** review available footage/images and determine whether editing, trimming, reframing, sequencing or reuse can meet the need before recommending new generation.
8. **Select the AI operation:** match the exact task to a currently supported model, operation, duration, aspect ratio, reference method, resolution, interface and plan entitlement.
9. **Prepare production instructions:** separate stable project/style instructions from the operation controller and the individual shot prompt.
10. **Validate and learn:** compare the result with the approved narration, biblical meaning, creative brief, technical requirements and quality gates. Record failures and lessons against the exact production version.

RhemaScript should proactively make the next useful recommendation. It should not repeatedly ask the user to specify routine filmmaking decisions that can be responsibly inferred. It must ask or stop only when a genuinely consequential ambiguity, missing approval, rights issue, or unsupported operation prevents safe progress.

## 4. Scripture-inspired human storytelling

The film should help viewers recognise their own lives through the truth of Scripture. It should not default to literal reenactment or generic motivational imagery.

For RS-PWW-001, the approved creative direction is an imaginative, surreal visual world inspired by Matthew 14:22-33 and connected to contemporary human experiences of pressure, fear, uncertainty, vulnerability, prayer and trust.

Project-specific visual restrictions:
- No literal depiction of Jesus, Peter, disciples, biblical clothing, biblical boats, biblical locations or reenactment.
- Modern human experience may transform into impossible, surreal environments and visual metaphors.
- A metaphor must not be presented as a historical or biblical event.
- Do not equate an arbitrary beam, silhouette or light effect with a literal depiction of Jesus.
- Do not imply that prayer guarantees instant removal of every practical problem.
- Preserve the passage's meaning, including Peter's dependence on Jesus and Jesus reaching out to catch him (Matthew 14:31).

## 5. Filmmaking intelligence requirements

### 5.1 Narration-first visual logic
The approved narration is the controlling story source. For every sentence and meaningful pause, RhemaScript must identify:
- literal meaning and biblical source connection;
- deeper spiritual idea;
- emotional intention and audience response;
- visual action that communicates the line;
- what the image must not imply;
- whether the shot is A-roll, B-roll, or a transition;
- audio, caption and edit requirements.

A shot must communicate, deepen or transition the narration. It must not compete with, contradict, repeat or interrupt the spoken message.

### 5.2 A-roll and B-roll
- A-roll is the primary subject/action that carries the story and emotional continuity.
- B-roll is a motivated insert that adds evidence, texture, context, scale or emotional detail.
- B-roll must belong to the same visual world and story.
- Do not use B-roll merely to fill time or decorate the narration.
- Any A-roll/B-roll percentage is an editorial guide, never a fixed rule. Story clarity and continuity determine the balance.

### 5.3 Cinematic grammar
Every shot plan must make deliberate choices about subject, shot size, composition, screen direction, lens/perspective where useful, camera movement, subject movement, depth, foreground/background, lighting, colour, transition and duration.

Avoid giving a short generation unit several unrelated actions. Prefer one dominant subject action, one primary camera behaviour and one clear emotional purpose per generation unit.

### 5.4 Audio and narration
- Maintain one approved, continuous narration master for the film unless an explicitly approved creative reason requires otherwise.
- Do not ask separate video generations to independently recreate or repeat the complete narration.
- Treat audio tags as performance/sound-design directions, not guaranteed executable controls.
- Native generated audio may be used for suitable ambience, Foley, music texture or other supporting sound where the selected model supports it.
- Generated dialogue must not duplicate, paraphrase or compete with the narration master.
- Verify the actual audio, words, omissions, repetitions, timing, levels, transitions and silence in the assembled film.
- Sound effects and music must not mask important speech.

### 5.5 Captions and closing message
- Use natural sentence case, never default all-capital captions.
- Use elegant Cormorant Garamond/classical serif treatment for the approved RS-PWW-001 direction.
- Base caption: raw cotton cream #F6F4EB; active spoken word: warm ochre-gold #E8B86D.
- Use restrained word-by-word emphasis, not constant bouncing or flashing.
- Synchronise captions against the final narration/audio timing, not guessed prompt timestamps.
- Preserve the approved closing treatment and Scripture reference; do not let the closing card interrupt the spoken message.

## 6. AI-tool intelligence: versioned capability and operation selection

### 6.1 Mandatory preflight
Before every generation/edit request, record:
- provider and interface (Gemini app or Google Flow);
- exact model and model version;
- task/operation;
- current model-operation compatibility;
- clip duration limits;
- aspect ratio and explicit UI selection;
- reference/input limits;
- resolution and upscaling path;
- audio/voice capabilities and limitations;
- subscription/region requirements where applicable;
- current credit/cost display where relevant;
- source URL, verification date and knowledge state;
- fallback operation if unsupported.

A prompt is not proof that a UI setting has been selected. The active model, aspect ratio, duration, resolution and operation in the actual interface are authoritative.

### 6.2 Google capability snapshot verified 2026-11-11

This is a dated knowledge snapshot, not a guarantee of a particular user's entitlement. Re-check official documentation and the signed-in interface before execution.

#### Gemini Apps — Gemini Omni Flash 1.2
- Text/video generation; 3-10 seconds generally and up to 15 seconds for eligible AI Ultra subscribers.
- Video-to-video editing and multi-turn editing.
- Aspect-ratio selection. Text-only prompts default to landscape; explicitly select portrait for Shorts.
- One uploaded video and up to five images can be used as references.
- Gemini can be asked to generate audio with video.
- Editing can remove/replace objects or characters, change camera angles, modify a scene and extend a generated video by up to another 10 seconds.
- Video generation requires an eligible Google AI plan for personal accounts or a qualifying Workspace licence for work/school accounts.

#### Google Flow — Gemini Omni Flash 1.2
- Without a Google AI subscription: text-to-video, frames-to-video, ingredients/references-to-video and video-to-video editing; both aspect ratios; 3-10 seconds.
- With Google AI Plus, Pro or Ultra: these operations can run 3-15 seconds.
- Omni Extend: 3-10-second extensions, up to three image references; requires Plus/Pro/Ultra and Flow on web.
- Omni 360p can be upscaled to 1080p; 4K upscaling is available to Ultra subscribers.
- Custom voice features and some Omni features may vary by region. Verify availability in the actual interface.

#### Google Flow — Veo 3.1 Lite
- Text-to-video and frames-to-video (first frame or first-and-last frame): both aspect ratios; 4, 6 or 8 seconds.
- Ingredients/references-to-video: 8 seconds.
- Video-to-video editing and video extension are not supported in the current capability guide.

#### Google Flow — Veo 3.1 Fast
- Text-to-video, frames-to-video and ingredients/references-to-video; both aspect ratios; 4, 6 or 8 seconds.
- Video-to-video editing and extension are not supported.
- Current documentation lists retirement on 2026-12-05; do not make it the default for new long-lived workflows.

#### Google Flow — Veo 3.1 Quality
- Text-to-video and frames-to-video (first frame or first-and-last frame); both aspect ratios; 4, 6 or 8 seconds.
- Ingredients/references-to-video, video-to-video editing and extension are not supported.
- Current documentation lists retirement on 2026-12-05; do not make it the default for new long-lived workflows.

#### Retired workflow
- The former Veo Extend workflow was retired on 2026-11-05. Use the currently documented Omni Flash 1.2 Extend workflow where available. Do not write prompts or SOPs that assume the retired Veo Extend path.

Official references:
- Gemini Apps video generation: https://support.google.com/gemini/answer/16126339
- Flow model capability matrix: https://support.google.com/flow/answer/16352836
- Create videos in Flow: https://support.google.com/flow/answer/16353334
- Edit videos and build scenes in Flow: https://support.google.com/labs/answer/16935718
- Veo model information: https://deepmind.google/models/veo/

### 6.3 Tool-selection rule
Do not force a fixed number or duration of clips. The story and edit determine shot length; the current model's supported durations determine generation units. Choose text-to-video, frames-to-video, ingredients, video-to-video, multi-turn editing or Extend according to the actual production need and verified support.

If the requested operation is unsupported, stop and propose a supported alternative. Do not silently substitute a different model, operation, aspect ratio or duration.

## 7. Prompt architecture

Keep three instruction layers separate:

1. **Project/creative bible:** source meaning, approved narration, audience, visual world, style bible, exclusions, continuity rules and immutable project decisions.
2. **Generation controller:** selected provider, interface, model, operation, aspect ratio, duration, resolution, references, audio mode and output requirements.
3. **Shot-specific prompt:** one shot's subject, composition, action, camera behaviour, lighting, atmosphere and exclusions.

Use the five practical visual prompt pillars—Style, Subject, Composition, Action, Lighting & Exclusions—inside each shot prompt. Use Role, Context, Task, Constraints and Output Format at the higher instruction/brief level. Do not overload a short generation prompt with unrelated actions or duplicate instructions.

## 8. Asset-first and source-to-final integrity

Preserve the mandatory chain:

Biblical source → approved interpretation → approved narration → narration/meaning map → visual concept → storyboard → audio-visual plan → tool preflight → shot prompt → generated or existing asset → edit → QC → final film.

Inspect existing assets first. Prefer trim, sequence, reframe, pacing, transitions, colour/audio treatment and reuse before recommending new generation. Each asset and prompt must retain source/version/provenance links.

## 9. Six existing approval gates remain mandatory

1. PROJECT_CREATIVE_DIRECTION
2. SCRIPT_BIBLICAL_ACCURACY
3. VISUAL_DEVELOPMENT
4. PRODUCTION_PLAN_PROMPT
5. GENERATION_AUTHORISATION
6. FINAL_FILM

Approval of narration or creative concept is not generation authorisation. No generation, external write, spending, publishing or deployment occurs without the relevant existing authority.

## 10. Quality and failure intelligence

Every production QC must check:
- biblical integrity and claim certainty;
- approved narration exactness, with no omissions, repetitions or paraphrases;
- narration-to-visual alignment and non-interruption;
- A-roll/B-roll motivation and continuity;
- visual style, subject, geography, motion and shot continuity;
- audio performance, sound effects, music and silence;
- caption spelling, case, timing, safe placement and legibility;
- correct closing message and Scripture reference;
- actual aspect ratio, runtime, resolution, frame rate and export integrity;
- rights, provenance, security and platform compliance.

Record failures with category, reproduction evidence, affected asset/prompt/model/version, cause status, corrective action and retest result. Do not claim root cause until evidence supports it. Link learning to the exact production version; do not claim that performance correlation proves causation.

## 11. Implementation boundary and next engineering steps

The existing repository currently has 15 capability contracts and deterministic, evidence-bound specialist assessments. The current CAP-09 handler validates supplied tool-evidence records but does not query Google, inspect a user's Flow interface, or independently verify model-operation compatibility. CAP-07 currently assesses supplied references/observations; it does not itself perform image/video analysis. CAP-05 and CAP-08 perform bounded structural checks; they do not autonomously create a film.

This document establishes the operating specification. The following code work remains separate and must be implemented and tested before claiming executable intelligence:
1. Add a versioned provider/model/operation capability registry with source URLs, checked-at timestamps, expiry/reverification policy and plan/region/interface conditions.
2. Extend CAP-09 to preflight exact model-operation-duration-aspect-ratio-reference compatibility and fail closed on stale or conflicting evidence.
3. Extend CAP-05/CAP-08 evidence contracts for narration-to-shot mapping, A-roll/B-roll purpose, audio/caption timing, edit continuity and generation-unit feasibility.
4. Extend CAP-07 with a clearly bounded visual-observation intake/analysis interface; do not claim automated visual understanding until a verified analyser exists.
5. Extend CAP-11 QC evidence and CAP-14 failure records to cover audio-visual interruption, narration duplication, tool mismatch and continuity failures.
6. Add tests for unsupported operations, retired models/workflows, stale capability evidence, missing portrait selection, plan/region uncertainty, generation-unit limits, narration duplication and human approval gates.

No live Google connection, account inspection, media generation, external platform write, spending, publishing or deployment is performed by this specification.

## 12. Acceptance criteria

This specification is acceptable only when:
- it composes existing CAP-01..CAP-15 without duplicating or bypassing them;
- Scripture facts, inference, interpretation and metaphor remain distinguishable;
- a creative recommendation is accompanied by a reason and constraints;
- the selected AI operation is proven compatible with current dated evidence;
- narration remains the master audio and visual plan;
- every shot has a narrative purpose and A-roll/B-roll designation;
- existing assets are assessed before new generation;
- all six approval gates and separate authorities remain intact;
- unverified capability, visual analysis, account entitlement or production outcomes are explicitly labelled as such.
