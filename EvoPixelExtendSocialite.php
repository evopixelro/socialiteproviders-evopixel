<?php

namespace SocialiteProviders\EvoPixel;

use SocialiteProviders\Manager\SocialiteWasCalled;

class EvoPixelExtendSocialite
{
    /**
     * Register the provider.
     *
     * @param \SocialiteProviders\Manager\SocialiteWasCalled $socialiteWasCalled
     */
    public function handle(SocialiteWasCalled $socialiteWasCalled)
    {
        $socialiteWasCalled->extendSocialite('evopixel', Provider::class);
    }
}
