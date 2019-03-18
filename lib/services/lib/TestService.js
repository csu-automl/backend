const keystone = require('keystone')
const TestModel = keystone.list('TestModel').model
const TestModel2 = keystone.list('TestModel2').model

const { WebError } = requireRoot('lib/errors')

class TestService {
  async createTestModel (data) {
    const test = await TestModel.create({
      name: data.name,
      field2: data.field2,
      status: 'ONE',
      field4: [ 'A', 'B', 'C' ]
    })
    return test.toObject()
  }

  async listModels (data) {
    const models = await TestModel.find()
    return models.map(m => m.toObject())
  }

  async getModel (id) {
    const model = TestModel.findOne({ _id: id })
    if (model == null) {
      throw new WebError('Model not found', 404)
    }
    return model
  }

  async createTestModel2 (data) {
    const testModel = await this.getModel(data.testModel)
    const test2 = await TestModel2.create({
      name: data.name,
      testModel
    })
    return test2.toObject()
  }
}

module.exports = TestService
