/**
 * Creating a sidebar enables you to:
 - create an ordered group of docs
 - render a sidebar for each doc of that group
 - provide next/previous navigation

 The sidebars can be generated from the filesystem, or explicitly defined here.

 Create as many sidebars as you want.
 */

// @ts-check

/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  yarahunter: [
    {
      type: 'html',
      value: 'Deepfence YaraHunter',
      className: 'sidebar-title',
    },    

    "yarahunter/index",
    "yarahunter/quickstart",

    {
      type: 'category',
      label: 'Using YaraHunter',
      items: [
        'yarahunter/using/build',
        'yarahunter/using/scan',
      ]
    },

    {
      type: 'category',
      label: 'Configuration',
      items: [
        'yarahunter/configure/cli',
        'yarahunter/configure/output',
        'yarahunter/configure/rules',
      ]
    },

  ],
};

module.exports = sidebars;
