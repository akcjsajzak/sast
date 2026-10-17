<h1>Users</h1>

<ul>
@foreach ($rows as $row)
    <li>{!! $row->name !!}</li>
@endforeach
</ul>

<p>Search term: {{ $q }}</p>
