Streamable SHA1
================
**[See the demo on my web site!](http://rubbingalcoholic.com/demos/sha1.html)**

I created this SHA1 class to solve a problem: many existing JavaScript SHA1
implementations choke and slow down when you try to hash large amounts of data.
This is because you typically have to pass all your data as one large string
into one function call. This is fine for a few kilobytes of data, but if you're
hashing megabytes or more of data, it takes a lot of CPU and memory to pass
huge strings around.

This SHA1 class gives you the option to stream data into your hash object over
multiple calls. The class buffers and processes blocks of 64 bytes, discarding
data that is no longer needed. This can speed things up significantly,
especially for applications that hash data generated in a loop.

This app is distributed under the MIT License and is free software.


Dependencies
------------
* [MooTools 1.4+](http://mootools.net/)


Usage
------------
By default, this class behaves like any other SHA1 class:

```javascript

    var hash = new sha1().hash('data data data ');
    // 65bd90d5e213e8d03e87b5be5eeda3bc81faa772
```

Use the streaming mode option to hash data over multiple iterations:

```javascript

    var _sha1 = new sha1();
    for (var i = 0; i < 3; i++)
        _sha1.hash('data ', {stream: true});

    var hash = _sha1.finalize();
    // 65bd90d5e213e8d03e87b5be5eeda3bc81faa772
```

Once you're done streaming data in, you call _sha1.finalize()_ to hash any
remaining data in the buffer and return the result.

Contributing
------------
Please let me know if you have any suggestions for improvements. If you're code
savvy, fork the project and make the change yourself! I will do my best to help
if something doesn't work or isn't clear. You can find me on Twitter
@rubbingalcohol