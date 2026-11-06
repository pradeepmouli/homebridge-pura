import type { API } from 'homebridge';

import { PuraPlatform } from './platform.js';
import { PLATFORM_NAME, LEGACY_PLATFORM_NAME } from './settings.js';

/**
 * This method registers the platform with Homebridge
 */
export default (api: API) => {
  api.registerPlatform(PLATFORM_NAME, PuraPlatform);
  api.registerPlatform(LEGACY_PLATFORM_NAME, PuraPlatform);
};
