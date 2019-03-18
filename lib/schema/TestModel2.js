var keystone = require('keystone')
var Types = keystone.Field.Types

/**
 * User Model
 * ==========
 */
var TestModel2 = new keystone.List('TestModel2')

TestModel2.add({
  name: { type: String, required: true, index: true },
  testModel: { type: Types.Relationship, ref: 'TestModel', initial: true, required: true }
})

/**
 * Registration
 */
TestModel2.defaultColumns = 'name, testModel'
TestModel2.register()
