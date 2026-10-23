import { defineEventHandler } from "nuxt/server";

/** Pages outside `content/` that the Docus sitemap cannot see. Keep in step with `app/pages/`. */
const PAGES = ["/keyspace"];

/** The Vue pages for `@nuxtjs/sitemap`, which puts them under `site.url` beside the Docus ones. */
export default defineEventHandler(() => PAGES);
