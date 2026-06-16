<?php

namespace App;

class Service
{
    public function run(): int
    {
        return 1;
    }

    public static function helper(): int
    {
        return 2;
    }

    public function unused(): int
    {
        return 0;
    }
}
