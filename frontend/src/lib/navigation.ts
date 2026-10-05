// Pages that show ONE upload's analysis: they get the dataset picker and keep ?upload= in links.
const DATA_PAGES = ['/logs'] // Dashboard and Investigations are company-wide

export function isDataPage(pathname: string): boolean {
  return DATA_PAGES.includes(pathname)
}
