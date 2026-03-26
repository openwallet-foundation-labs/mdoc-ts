<h1 align="center" ><b>mDOC and mDL - TypeScript</b></h1>

[ISO 18013-5](https://www.iso.org/standard/69084.html) defines mDL (mobile Driver’s Licenses): an ISO standard for digital driver licenses.

This is a JavaScript library for Node.JS, browers and React Native to issue and verify mDL [CBOR encoded](https://cbor.io/) documents in accordance with ISO 18013-7

<p align="center">
  <a href="https://typescriptlang.org">
    <img src="https://img.shields.io/badge/%3C%2F%3E-TypeScript-%230074c1.svg" />
  </a>
  <a href="https://www.npmjs.com/package/@owf/mdoc">
    <img src="https://img.shields.io/npm/v/@owf/mdoc" />
  </a>
</p>

<p align="center">
  <a href="#installation">Installation</a> 
  &nbsp;|&nbsp;
  <a href="#contributing">Contributing</a>
  &nbsp;|&nbsp;
  <a href="#license">License</a>
  &nbsp;|&nbsp;
  <a href="#credits">Credits</a>
</p>

## Installation

```bash
npm i @owf/mdoc
```

## React Native Support

When using this library in React Native you may need to add a polyfill for TextDecoder. 

You can confirm this by checking if `global.TextDecoder` is available. It should be available for React Native > 0.85 or Expo SDK > 52.

If it is not available, make sure to add a polyfill like [this one](https://github.com/EvanBacon/text-decoder).

## Contributing

Is there something you'd like to fix or add? Great, we love community
contributions! To get involved, please follow our [contribution guidelines](./CONTRIBUTING.md).

## License

This project is licensed under the Apache License Version 2.0 (Apache-2.0).

## Credits

Thanks to:

- [auth0/mdl](https://github.com/auth0-lab/mdl) for the mdl implementation on which this repository is based.
- [auer-martin](https://github.com/auer-martin) for removing node.js dependencies and providing a pluggable crypto interface
