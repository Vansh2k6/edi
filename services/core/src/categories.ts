import { readFileSync } from 'node:fs';
import { dataCategoryRegistrySchema, type DataCategory } from '@pv/schemas';

/**
 * Data categories are configuration, not code (D-004): a new category is a JSON
 * edit, validated at load. An invalid registry stops the process rather than
 * silently dropping a category, because a missing category would quietly change
 * how requests are classified.
 */
export function loadCategories(path: string): DataCategory[] {
  const raw = readFileSync(path, 'utf8');
  const parsed = dataCategoryRegistrySchema.safeParse(JSON.parse(raw) as unknown);
  if (!parsed.success) {
    const fields = parsed.error.issues.map((issue) => issue.path.map(String).join('.')).join(', ');
    throw new Error(`data-category registry at ${path} is invalid: ${fields}`);
  }
  const seen = new Set<string>();
  for (const category of parsed.data) {
    if (seen.has(category.data_category_id)) {
      throw new Error(`data-category registry at ${path} repeats ${category.data_category_id}`);
    }
    seen.add(category.data_category_id);
  }
  return parsed.data;
}

export function findCategory(categories: readonly DataCategory[], id: string): DataCategory | undefined {
  return categories.find((category) => category.data_category_id === id);
}
