import { BentoGrid, BentoItem } from "@/components/sieve/shell/bento-grid";
import { Card } from "@/components/sieve/shell/card";
import { Page } from "@/components/sieve/shell/page";

// Foundation placeholder. Slice S2 replaces this page with the live Home.
export default function HomePage() {
  return (
    <Page title="Home">
      <BentoGrid>
        <BentoItem span="two-thirds">
          <Card title="Apps being sieved" state={{ kind: "loading" }} className="min-h-80" />
        </BentoItem>
        <BentoItem span="third">
          <Card title="Right now" state={{ kind: "loading" }} className="min-h-80" />
        </BentoItem>
        <BentoItem span="third">
          <Card title="Top apps" state={{ kind: "loading" }} className="min-h-64" />
        </BentoItem>
        <BentoItem span="two-thirds">
          <Card title="When apps are busy" state={{ kind: "loading" }} className="min-h-64" />
        </BentoItem>
      </BentoGrid>
    </Page>
  );
}
