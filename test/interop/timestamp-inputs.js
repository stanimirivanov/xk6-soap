import { checkPlainBuilds } from './plain-echo.js';

export { buildEcho, options, soapVersions } from './plain-echo.js';

export const operations = {
  success: open('./testdata/timestamp/echo-success.xml'),
  fault: open('./testdata/matrix/echo-fault.xml'),
};

export default function () {
  checkPlainBuilds(operations, 'TIMESTAMP_PRIVATE_SENTINEL');
}
