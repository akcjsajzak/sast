<?php

namespace App\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class SearchController
{
    public function search(Request $request, $em): Response
    {
        $term = $request->query->get('term');

        // SQL/DQL injection via Doctrine query builder
        $qb = $em->createQueryBuilder();
        $qb->select('u')->from('User', 'u')->where('u.name = ' . $term);

        $result = $qb->getQuery()->getResult();

        return new Response('<pre>' . $result . '</pre>');
    }

    public function reflect(Request $request): Response
    {
        $msg = $request->request->get('msg');
        return new Response('<html><body>' . $msg . '</body></html>');
    }
}
