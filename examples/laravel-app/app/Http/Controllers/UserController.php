<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class UserController extends Controller
{
    public function search(Request $request)
    {
        $q = $request->input('q');

        // SQL injection via raw query builder
        $rows = DB::table('users')->whereRaw("name LIKE '%" . $q . "%'")->get();

        // SQL injection via raw select
        $users = DB::select("SELECT * FROM users WHERE name = '" . $q . "'");

        return view('users.index', ['rows' => $rows, 'users' => $users]);
    }

    public function download(Request $request)
    {
        $filename = $request->query('file');

        // Path traversal via storage download
        $path = storage_path('app/') . $filename;
        return response()->download($path);
    }

    public function run(Request $request)
    {
        // Command injection
        $cmd = $request->input('command');
        shell_exec('php artisan ' . $cmd);
    }
}
