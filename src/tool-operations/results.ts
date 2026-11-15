/**
 * Text for the model plus structured details for agent harnesses. A failure throws instead:
 * Pi records every returned value as a successful call.
 */
export interface ToolResult<Details> {
  content: Array<{ type: "text"; text: string }>;
  details: Details;
}

/**
 * Removes terminal and line control bytes from text crossing an agent boundary.
 * @param text - Text to sanitize.
 * @returns {string} Text without control bytes.
 */
export function sanitizeToolText(text: string): string {
  return text.replaceAll(/\p{Cc}/gu, " ");
}

/**
 * Escapes every code point that could break or hide a result line, and the backslash itself.
 * @param text - Caller text echoed into a result line.
 * @returns {string} The text on one visible line.
 */
export function escapeToolText(text: string): string {
  return text.replaceAll(/[\p{Cc}\p{Cf}\p{Co}\p{Cn}\p{Zl}\p{Zp}\\]/gu, (character) =>
    character === "\\" ? "\\\\" : `\\u{${character.codePointAt(0)?.toString(16) ?? ""}}`,
  );
}

export function content(text: string): Array<{ type: "text"; text: string }> {
  return [{ type: "text", text }];
}
