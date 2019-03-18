var keystone = require('keystone')
var Types = keystone.Field.Types

/**
 * User Model
 * ==========
 */
var TestModel = new keystone.List('TestModel')

TestModel.add({
  name: { type: String, required: true, index: true },
  field2: { type: Number, initial: true, required: true },
  status: {
    type: Types.Select,
    required: true,
    initial: true,
    options: ['ONE', 'TWO', 'THREE', 'FOUR']
  },
  field4: { type: Types.TextArray }
})

/**
 * Registration
 */
TestModel.defaultColumns = 'name, field2, status, field4'
TestModel.register()
