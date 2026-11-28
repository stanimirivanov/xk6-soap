import { checkPlainBuilds } from './plain-echo.js';

export { buildEcho, options, soapVersions } from './plain-echo.js';

export const operation = open('./testdata/receive/echo-success.xml');
export const expectedValue = 'synthetic';

export default function () {
  checkPlainBuilds({success: operation}, expectedValue);
}
