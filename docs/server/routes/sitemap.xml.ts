import docusSitemap from "docus/server/routes/sitemap.xml";
import { inferSiteURL } from "docus/utils/meta";

/** Pages outside `content/` that the Docus sitemap cannot see. Keep in step with `app/pages/`. */
const PAGES = ["/keyspace"];

/** The Docus sitemap lists content collections only, so the Vue pages are appended here. */
export default defineEventHandler(async (event) => {
  const xml = String(await docusSitemap(event));
  const siteUrl = inferSiteURL() ?? "";
  const entries = PAGES.map((path) => `  <url>\n    <loc>${siteUrl}${path}</loc>\n  </url>`).join("\n");
  return xml.replace("</urlset>", `${entries}\n</urlset>`);
});
