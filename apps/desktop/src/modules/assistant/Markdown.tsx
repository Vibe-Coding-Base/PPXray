// Model replies, rendered as the Markdown they are.
//
// The assistant writes lists, tables and inline code because that is how
// models write; showing the source meant every answer arrived full of `**`
// and `|---|`. This renders it with Mantine's own typography so a reply
// looks like the rest of the app rather than like a web page dropped into it.
//
// Raw HTML is deliberately not enabled. The text comes from a remote service,
// and `react-markdown` ignores embedded HTML unless `rehype-raw` is added —
// leaving that out is what keeps a reply from being able to inject markup.

import { Anchor, Blockquote, Code, List, Table, Text, Title } from "@mantine/core";
import ReactMarkdown, { type Components } from "react-markdown";
import remarkGfm from "remark-gfm";

/** Mantine equivalents for the elements a model actually emits. */
const COMPONENTS: Components = {
  p: ({ children }) => (
    <Text size="sm" mb="xs">
      {children}
    </Text>
  ),
  strong: ({ children }) => (
    <Text component="span" size="sm" fw={700}>
      {children}
    </Text>
  ),
  em: ({ children }) => (
    <Text component="span" size="sm" fs="italic">
      {children}
    </Text>
  ),
  h1: ({ children }) => (
    <Title order={5} mt="sm" mb={4}>
      {children}
    </Title>
  ),
  h2: ({ children }) => (
    <Title order={5} mt="sm" mb={4}>
      {children}
    </Title>
  ),
  h3: ({ children }) => (
    <Title order={6} mt="sm" mb={4}>
      {children}
    </Title>
  ),
  ul: ({ children }) => (
    <List size="sm" spacing={2} mb="xs">
      {children}
    </List>
  ),
  ol: ({ children }) => (
    <List size="sm" spacing={2} type="ordered" mb="xs">
      {children}
    </List>
  ),
  li: ({ children }) => <List.Item>{children}</List.Item>,
  blockquote: ({ children }) => (
    <Blockquote p="xs" my="xs">
      {children}
    </Blockquote>
  ),
  a: ({ children, href }) => (
    // Model output can contain links; they open in the user's browser rather
    // than navigating the app shell out of existence.
    <Anchor href={href} target="_blank" rel="noreferrer noopener" size="sm">
      {children}
    </Anchor>
  ),
  code: ({ className, children }) => {
    // `react-markdown` marks fenced blocks with a `language-*` class; inline
    // code has none.
    const fenced = /language-/.test(className ?? "");
    return fenced ? (
      <Code block style={{ fontSize: "var(--ppxray-text-dense)", whiteSpace: "pre-wrap" }}>
        {children}
      </Code>
    ) : (
      <Code style={{ fontSize: "var(--ppxray-text-dense)" }}>{children}</Code>
    );
  },
  // A model asked about a log answers with tables constantly, so they get
  // real ones - and their own horizontal scroll, since hostname columns are
  // wide and the chat panel is not.
  table: ({ children }) => (
    <div style={{ overflowX: "auto", marginBottom: "0.5rem" }}>
      <Table withTableBorder withColumnBorders verticalSpacing={2} horizontalSpacing={6}>
        {children}
      </Table>
    </div>
  ),
  thead: ({ children }) => <Table.Thead>{children}</Table.Thead>,
  tbody: ({ children }) => <Table.Tbody>{children}</Table.Tbody>,
  tr: ({ children }) => <Table.Tr>{children}</Table.Tr>,
  th: ({ children }) => <Table.Th>{children}</Table.Th>,
  td: ({ children }) => <Table.Td>{children}</Table.Td>,
  hr: () => <hr style={{ border: 0, borderTop: "1px solid var(--ppxray-border)" }} />,
};

export function Markdown({ children }: { children: string }) {
  return (
    <ReactMarkdown remarkPlugins={[remarkGfm]} components={COMPONENTS}>
      {children}
    </ReactMarkdown>
  );
}
