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
      { title: "Getting Started", href: "/docs/getting-started-guide" },
      { title: "Why Soroban", href: "/docs/why-soroban" },
    ],
  },
  {
    title: "Core Concepts",
    children: [
      { title: "Constant Time Notes", href: "/docs/constant-time-notes" },
      { title: "Upgrading to V2", href: "/docs/upgrading-from-v1-to-v2" },
      { title: "Developer FAQ", href: "/docs/developer-faq" },
    ],
  },
  {
    title: "Math & Cryptography",
    children: [
      { title: "Non-Native Math", href: "/docs/non-native-math" },
      { title: "Polynomial Operations", href: "/docs/polynomial-operations" },
      { title: "Poseidon2", href: "/docs/poseidon2" },
      { title: "Bulletproofs", href: "/docs/bulletproofs" },
      { title: "Rescue", href: "/docs/rescue" },
      { title: "Cyclotomic", href: "/docs/cyclotomic" },
      { title: "Halo2 Perm", href: "/docs/halo2_perm" },
      { title: "Non Native Add", href: "/docs/non_native_add" },
      { title: "FRI", href: "/docs/fri" },
      { title: "G2 Subgroup Validation", href: "/docs/g2_subgroup" },
      { title: "KZG Commitment Generation", href: "/docs/kzg_commit" },
      { title: "Inner Product Argument (IPA)", href: "/docs/ipa" },
      { title: "Batch KZG Verification", href: "/docs/batch_kzg" },
      { title: "Fiat-Shamir Transcript Rules", href: "/docs/fiat_shamir" },
    ],
  },
  {
    title: "Integration & Verification",
    children: [
      { title: "CAP-0075 Integration", href: "/docs/cap0075-integration-guide" },
      { title: "ASP Integration", href: "/docs/ASP_Integration" },
      { title: "Groth16 Verifier", href: "/docs/groth16-verifier-guide" },
      { title: "Cross-Contract Verification", href: "/docs/cross-contract-verification" },
    ],
  },
  {
    title: "Reference",
    children: [
      { title: "ZK Cryptography Glossary", href: "/docs/zk-cryptography-glossary" },
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
