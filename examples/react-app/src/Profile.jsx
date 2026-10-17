import React from 'react';

export default function Profile() {
  // DOM XSS: the bio comes from the query string and is injected as raw HTML.
  const params = new URLSearchParams(location.search);
  const bio = params.get('bio');
  const next = params.get('next');

  return (
    <div>
      <div dangerouslySetInnerHTML={{ __html: bio }} />
      <a href={next}>continue</a>
    </div>
  );
}
