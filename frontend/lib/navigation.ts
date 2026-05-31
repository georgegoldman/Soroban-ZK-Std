export interface NavItem {
  title: string;
  href?: string;
  children?: NavItem[];
}

export const navigation: NavItem[] = [
  {
    title: "Getting Started",
    children: [
      { title: "Introduction", href: "/docs" },
      { title: "Installation", href: "/docs/installation" },
      { title: "Quick Start", href: "/docs/quick-start" },
    ],
  },
  {
    title: "Core Concepts",
    children: [
      { title: "Architecture Overview", href: "/docs/architecture" },
      { title: "Field Arithmetic", href: "/docs/field-arithmetic" },
      { title: "Elliptic Curves", href: "/docs/elliptic-curves" },
      { title: "Scalar Validation", href: "/docs/scalar-validation" },
    ],
  },
  {
    title: "API Reference",
    children: [
      { title: "API Reference", href: "/docs/api-reference" },
      { title: "Polynomial Operations", href: "/docs/polynomial-operations" },
      { title: "Pairing", href: "/docs/pairing" },
      { title: "Poseidon2", href: "/docs/poseidon2" },
      { title: "Non-Native Math", href: "/docs/non-native-math" },
      { title: "ElGamal Encryption", href: "/docs/elgamal" },
    ],
  },
  {
    title: "Tools",
    children: [
      { title: "Gas Calculator", href: "/tools/gas-calculator" },
      { title: "Math Rendering", href: "/docs/math-rendering" },
    ],
  },
  {
    title: "Guides",
    children: [
      { title: "CAP-0075 Integration", href: "/docs/cap0075" },
      { title: "ASP Integration", href: "/docs/asp-integration" },
      { title: "Shielded Assets", href: "/docs/shielded-assets" },
    ],
  },
  {
    title: "Reference",
    children: [
      { title: "ZK Cryptography Glossary", href: "/docs/glossary" },
    ],
  },
];

export function getFlatNavItems(): { title: string; href: string }[] {
  const result: { title: string; href: string }[] = [];
  for (const section of navigation) {
    if (section.children) {
      for (const child of section.children) {
        if (child.href) {
          result.push({ title: child.title, href: child.href });
        }
      }
    }
  }
  return result;
}
