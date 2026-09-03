/** Shortens long decimals for display: `1273542909…9395957213`. */
export function shortDecimal(value: bigint, keep = 10): string {
  const text = value.toString();
  return text.length > keep * 2 + 1 ? `${text.slice(0, keep)}…${text.slice(-keep)}` : text;
}
