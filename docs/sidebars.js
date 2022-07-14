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
  yaradare: [
    {
      type: 'html',
      value: 'Deepfence Yaradare',
      className: 'sidebar-title',
    },    

    "yaradare/index",
    "yaradare/quickstart",

    {
      type: 'category',
      label: 'Using YaRadare',
      items: [
        'yaradare/using/build',
        'yaradare/using/scan',
      ]
    },

    {
      type: 'category',
      label: 'Configuration',
      items: [
        'yaradare/configure/cli',
        'yaradare/configure/output',
        'yaradare/configure/rules',
      ]
    },

  ],
};

module.exports = sidebars;
