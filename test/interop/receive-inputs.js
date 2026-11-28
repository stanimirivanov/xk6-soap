import { checkPlainBuilds } from './plain-echo.js';

export { buildEcho, options, soapVersions } from './plain-echo.js';

export const operations = {
  success: open('./testdata/receive/echo-success.xml'),
  fault: open('./testdata/matrix/echo-fault.xml'),
};

export default function () {
  checkPlainBuilds(operations, 'synthetic');
}
