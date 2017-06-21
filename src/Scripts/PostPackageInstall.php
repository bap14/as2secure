<?php
/**
 * Copyright (c) 2017 Brett Patterson
 *
 * @author Brett Patterson <bap14@users.noreply.github.com>
 */

namespace Bap14\AS2Secure\Scripts;

use Composer\Installer\PackageEvent;

class PostPackageInstall
{
    public static function createMessageDirs(PackageEvent $event) {
        $package = $event->getOperation()->getPackage();
        if ($package->getName() == 'bap14/as2secure') {
            mkdir(realpath(dirname(__FILE__)) . DIRECTORY_SEPARATOR . '_private', 0777);
            mkdir(realpath(dirname(__FILE__)) . DIRECTORY_SEPARATOR . '_messages', 0777);
        }
    }
}