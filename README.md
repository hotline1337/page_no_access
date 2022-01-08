# Page Guard No Access

## Proof of Concept
We specify the section by using it's name, we encrypt it and set the protection to **NO_ACCESS**. The pages will be decrypted on their very first access. If the **RIP** will be outside the valid module the program will **fail and crash**.

## Usage

```cpp
#include "section.hpp"

auto main(void) -> int
{
    page_guard::section::initialize_protection(".text");
    
    /* ... */
    
    return EXIT_SUCCESS;
}
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[GPL-3.0](https://choosealicense.com/licenses/gpl-3.0/)
