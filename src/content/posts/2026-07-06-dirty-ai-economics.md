---
title: 'The Uncomfortable Economics Behind the AI Boom'
published: 2026-07-06 10:00:00+00:00
draft: false
description: 'My perspective on the AI infrastructure arms race: why the technology can be real, useful, and transformative while the current economics still look fragile.'
tags: ['AI', 'Economics', 'Infrastructure', 'Technology', 'Markets']
series: ''
toc: true
---

I use AI every day, and I still think we are living through one of the most important technology shifts of my lifetime. But the more I look at the money behind the boom, the harder it becomes to ignore a simple tension: **AI can be genuinely useful while the business model around it is still dangerously overbuilt.**

That is the part of the current cycle that feels uncomfortable. The public conversation is mostly about model capability, benchmarks, agents, copilots, and automation. The quieter story is about power, chips, depreciation, data centers, financing, and the amount of revenue required to justify this buildout.

My current view is not that AI is fake. It is that the market may be confusing _technical inevitability_ with _economic inevitability_.

---

## The promise is real, but the bill is also real

The bullish case for AI is easy to understand. Better models can compress research time, generate code, summarize documents, automate support, improve search, assist doctors, accelerate science, and give individuals leverage that used to require teams. I have personally felt that leverage. As a builder, it is obvious that AI changes the way software gets written and ideas get prototyped.

But there is a difference between saying "this is useful" and saying "every dollar being spent on infrastructure will earn an attractive return."

The AI boom is not a lightweight software boom. It is a physical infrastructure boom wearing a software narrative. Every query, every generated image, every long context workflow, every agent loop, and every training run consumes compute. That compute needs GPUs, networking, memory, cooling, real estate, electricity, and financing.

Traditional software has beautiful economics because the marginal cost of serving another user can be tiny. AI does not automatically inherit that structure. In many cases, more usage means more inference cost. Better answers often require larger models, longer context, more tool calls, more retries, and more tokens. The cost curve can improve, but it does not disappear.

That is why I think the most important AI question is no longer just: **Can the model do it?**

It is also: **Can the model do it profitably, repeatedly, and at global scale?**

---

## The capex cycle is the real story

The biggest technology companies are spending at a pace that looks less like a normal product cycle and more like a historic infrastructure race. Hyperscaler capital expenditure has moved from being one line item in a cloud growth story to becoming the central force shaping chips, energy, construction, debt markets, and public equity valuations.

The optimistic version is straightforward: demand is so large that companies must build ahead of it. If they do not, they risk missing the platform shift. Nobody wants to be the company that underbuilt during the birth of the next computing layer.

But the uncomfortable version is just as simple: when everyone builds at once, the industry can create capacity faster than it creates profitable demand.

That is where the bubble risk lives. Not in the idea that AI has no value, but in the possibility that too much capital is being pulled forward before the revenue model is mature enough to support it.

This reminds me of a pattern that appears in many technology cycles:

1. A real breakthrough appears.
2. Capital markets correctly recognize that it matters.
3. Investors extrapolate too aggressively.
4. Suppliers make money first.
5. Builders absorb the depreciation later.
6. The market eventually asks who is actually earning durable cash flow.

During the internet buildout, fiber was real. The internet was real. The demand was real. But some infrastructure was still financed too early, too expensively, or by companies that could not survive the gap between vision and cash flow.

AI may rhyme with that history. The technology can win while many investments around it disappoint.

---

## The numbers that changed my mind

Here are the metrics I keep coming back to. They are imperfect because every company reports AI infrastructure differently, but the direction is hard to miss: the physical layer of AI is scaling faster than the proven revenue layer.

| Signal                                               |                                           Metric | Why it matters                                                                                                                                                    | Source                                                                                                                                    |
| ---------------------------------------------------- | -----------------------------------------------: | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| Microsoft FY2025 additions to property and equipment |         **$64.6B**, up from **$44.5B** in FY2024 | The cash-flow statement shows a $20B step-up in physical infrastructure spend, and management explicitly ties future capex to cloud growth and AI infrastructure. | [Microsoft 2025 Annual Report](https://www.microsoft.com/investor/reports/ar25/index.html)                                                |
| Alphabet 2026 capex guide                            |                                  **$175B–$185B** | Alphabet says 2026 capex is being lifted to meet AI and cloud demand; that is an infrastructure budget on the scale of a large industrial economy.                | [Alphabet Q4 2025 results, SEC Exhibit 99.1](https://www.sec.gov/Archives/edgar/data/1652044/000165204426000012/googexhibit991q42025.htm) |
| Amazon 2026 capex plan                               |                                  about **$200B** | Amazon says it is willing to accept short-term free-cash-flow pressure because it believes AI can become a major AWS growth pillar.                               | [Amazon 2025 Annual Report](https://s2.q4cdn.com/299287126/files/doc_financials/2026/ar/Amazon-2025-Annual-Report.pdf)                    |
| Meta property and equipment, net                     | **$176.4B** in 2025, up from **$121.3B** in 2024 | Meta's balance sheet shows how quickly servers, network assets, buildings, and construction-in-progress are becoming core to the AI strategy.                     | [Meta 2025 Form 10-K](https://www.sec.gov/Archives/edgar/data/1326801/000162828026003942/meta-20251231.htm)                               |
| Global data-center electricity demand                |     projected to reach about **945 TWh by 2030** | The AI story is no longer just software; the International Energy Agency expects data-center electricity consumption to roughly double by 2030.                   | [IEA: Energy demand from AI](https://www.iea.org/reports/energy-and-ai/energy-demand-from-ai)                                             |

<div class="ai-economics-chart" aria-label="Selected AI infrastructure metrics, in billions of US dollars except electricity demand in terawatt-hours">
  <style>
    .ai-economics-chart { margin: 1.5rem 0; padding: 1rem; border: 1px solid var(--color-border, #333); border-radius: 12px; }
    .ai-economics-chart h3 { margin-top: 0; }
    .ai-economics-chart .row { display: grid; grid-template-columns: 8rem 1fr 5rem; gap: .75rem; align-items: center; margin: .65rem 0; }
    .ai-economics-chart .bar { height: 1.1rem; border-radius: 999px; background: linear-gradient(90deg, #7c3aed, #06b6d4); min-width: 2px; }
    .ai-economics-chart .note { font-size: .85rem; opacity: .8; margin-bottom: 0; }
  </style>
  <h3>Selected AI infrastructure scale markers</h3>
  <div class="row"><strong>Microsoft</strong><div class="bar" style="width: 32.3%"></div><span>$64.6B</span></div>
  <div class="row"><strong>Alphabet</strong><div class="bar" style="width: 90%"></div><span>$180B*</span></div>
  <div class="row"><strong>Amazon</strong><div class="bar" style="width: 100%"></div><span>$200B*</span></div>
  <div class="row"><strong>Meta PPE</strong><div class="bar" style="width: 88.2%"></div><span>$176.4B</span></div>
  <p class="note">*Alphabet and Amazon are 2026 capex guidance/plans. Microsoft is FY2025 additions to property and equipment. Meta is 2025 net property and equipment, not annual capex, so it is shown as a balance-sheet scale marker rather than a directly comparable spend figure.</p>
</div>

The chart is intentionally simple. It is not trying to compare identical accounting categories; it is trying to show the magnitude of the bet. Once annual infrastructure plans are measured in the tens or hundreds of billions, AI stops looking like a normal SaaS upgrade cycle and starts looking like a capital-intensive platform transition.

## The supplier-builder split worries me

One thing I keep watching is the difference between the companies selling the picks and shovels and the companies buying them.

Chipmakers, memory suppliers, networking companies, data center operators, and power infrastructure firms can benefit immediately from the buildout. They get paid when orders are placed. Their revenue is tied to the urgency of the race.

The hyperscalers and AI application companies have a harder problem. They must convert that spend into revenue, margin, customer retention, and long-term return on invested capital. They are not only buying hardware; they are buying an obligation to keep that hardware productive before it becomes obsolete.

That distinction matters because GPUs do not behave like timeless assets. They depreciate economically as new chips arrive, as model architectures become more efficient, and as customers demand better price-performance. A data center full of cutting-edge accelerators can become strategically necessary and financially heavy at the same time.

This is the part of the AI story that does not fit neatly into the usual software multiple. If a company spends tens or hundreds of billions on AI infrastructure, the market eventually needs to see more than demos. It needs to see utilization, pricing power, gross margin, and a believable path from capex to cash flow.

Until then, the suppliers may look brilliant while the builders quietly carry the risk.

---

## Revenue has to catch up with ambition

The AI industry needs a massive new revenue pool. Not just attention. Not just usage. Not just free-tier excitement. Actual high-margin revenue.

There are only a few obvious places it can come from:

- enterprises paying meaningfully more for AI-native productivity;
- consumers accepting recurring subscriptions beyond the current early-adopter base;
- cloud customers paying premium prices for AI compute;
- advertisers receiving enough incremental performance to fund AI features;
- software companies raising prices because AI makes their products materially better;
- entirely new workflows that did not exist before.

Some of this will happen. The question is whether it happens fast enough and with enough margin to justify the infrastructure already being built.

I am skeptical of arguments that count all AI usage as proof of economic demand. Free or subsidized usage can reveal interest, but it does not prove profitability. A user asking a model to generate code, images, or research summaries may love the product while still being served at a price that barely covers compute, or does not cover it at all.

This is why I think the next phase of AI will be less about model launch excitement and more about unit economics. The winners will not simply be the companies with the most impressive demos. They will be the companies that can answer hard questions:

- What does each interaction cost?
- How much of that cost is passed to the customer?
- Does quality improve faster than cost?
- Does the product create measurable willingness to pay?
- Can inference be optimized without destroying user experience?
- Can revenue scale faster than depreciation?

If those answers are weak, the story becomes fragile.

---

## Circular confidence is not the same as demand

Another thing that makes me cautious is how much of the AI economy appears interconnected. Cloud providers invest in AI companies. AI companies commit to buying cloud capacity. Chip suppliers finance or support ecosystem partners. Startups announce enormous infrastructure plans before their own revenue base is proven.

Some of this is normal ecosystem building. Platform shifts often require strategic partnerships. But there is a line where partnerships start to look like circular confidence: everyone validates everyone else, and the market treats the circle itself as proof of demand.

That can work for a while. It can even be rational if the future arrives quickly enough. But it also creates a risk that reported demand is partly financed by the same ecosystem that benefits from reporting it.

For me, the cleanest signal is not how many billion-dollar deals get announced. It is how much independent, repeat, unsubsidized customer demand appears outside the circle.

If enterprises are paying because AI reduces real costs or creates real revenue, that is durable. If consumers are paying because the product becomes indispensable, that is durable. If developers are paying because AI compute becomes a core production dependency, that is durable.

But if the economics depend mostly on strategic funding, bundled credits, headline partnerships, or fear of missing out, then the system is more fragile than it looks.

---

## My personal stance: bullish on AI, cautious on the boom

I do not want to be misunderstood. I am not anti-AI. I am probably more convinced than ever that AI will reshape software, security, education, research, design, and knowledge work. I expect the models to get better. I expect inference to get cheaper. I expect new products to emerge that feel obvious in hindsight.

But I am cautious about the assumption that every layer of the current boom deserves today’s valuation or today’s spending pace.

The distinction I keep coming back to is this:

> A technology can be inevitable while the first financial structure built around it is unsustainable.

That is not a contradiction. It is almost normal. Railroads, telecom, the internet, solar, crypto, and cloud all had moments where the long-term direction was right but the near-term capital cycle became distorted.

AI may be entering that kind of moment. The useful parts will survive. The wasteful parts will be written down. The companies with real distribution, strong balance sheets, efficient infrastructure, and products that customers actually pay for will compound. The companies depending on hype, cheap capital, and vague automation promises will struggle.

---

## What I am watching next

To understand whether the AI boom is healthy or overextended, I am watching five signals.

### 1. Inference margins

Training gets the headlines, but inference is where everyday economics show up. If usage grows and margins improve, that is a strong sign. If usage grows but losses grow with it, the business model is weaker than the product.

### 2. Enterprise renewals

Pilots are easy. Renewals are harder. I want to see whether companies renew AI contracts after the novelty fades and procurement teams ask for measurable ROI.

### 3. Capex discipline

The first company to slow spending may look weak in the short term, but discipline could become a strength if the industry overbuilds. I am watching whether leaders can say "no" to unnecessary capacity.

### 4. Power and supply constraints

AI is now tied to energy infrastructure. If power availability, grid connections, cooling, or construction timelines become bottlenecks, the software story becomes an industrial story.

### 5. Real application revenue

The most important signal is not how many people try AI. It is how many workflows become valuable enough that customers pay without subsidies.

---

## Sources I used for the data

- [Microsoft 2025 Annual Report](https://www.microsoft.com/investor/reports/ar25/index.html)
- [Alphabet Q4 2025 results filed with the SEC](https://www.sec.gov/Archives/edgar/data/1652044/000165204426000012/googexhibit991q42025.htm)
- [Amazon 2025 Annual Report](https://s2.q4cdn.com/299287126/files/doc_financials/2026/ar/Amazon-2025-Annual-Report.pdf)
- [Meta 2025 Form 10-K filed with the SEC](https://www.sec.gov/Archives/edgar/data/1326801/000162828026003942/meta-20251231.htm)
- [International Energy Agency: Energy demand from AI](https://www.iea.org/reports/energy-and-ai/energy-demand-from-ai)

---

## Final thought

The AI boom has two truths living side by side.

The first truth is that AI is a real technological shift. It gives individuals and companies new leverage, and it will change how a lot of work gets done.

The second truth is that the current buildout is making an enormous financial bet before the full revenue model is proven.

I believe both at the same time.

So my perspective is simple: **build with AI, learn it deeply, use it aggressively, but do not confuse capability with economics.** The winners of this cycle will not be the loudest believers. They will be the people and companies that understand both the magic and the math.
