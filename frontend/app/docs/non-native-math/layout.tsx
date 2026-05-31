import { DocsLayout } from "@/components/DocsLayout";

export default function NonNativeMathLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <DocsLayout>{children}</DocsLayout>;
}
